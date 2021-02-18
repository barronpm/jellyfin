using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Data.Entities;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Entities.Audio;
using MediaBrowser.Controller.Events.Library;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Entities;
using MediaBrowser.Model.Session;
using Microsoft.Extensions.Logging;
using Rebus.Sagas;

namespace Jellyfin.Server.Implementations.Sagas
{
    /// <summary>
    /// Manages grouping library item change events to send to clients.
    /// </summary>
    public class LibraryChangedNotifierSaga : Saga<LibraryChangedSagaData>,
        IAmInitiatedBy<ItemAddedEventArgs>,
        IAmInitiatedBy<ItemChangedEventArgs>,
        IAmInitiatedBy<ItemRemovedEventArgs>
    {
        private const int LibraryUpdateDuration = 30000;

        private readonly ILogger<LibraryChangedNotifierSaga> _logger;
        private readonly ISessionManager _sessionManager;
        private readonly ILibraryManager _libraryManager;
        private readonly IUserManager _userManager;

        /// <summary>
        /// Initializes a new instance of the <see cref="LibraryChangedNotifierSaga"/> class.
        /// </summary>
        /// <param name="logger">The logger.</param>
        /// <param name="sessionManager">The session manager.</param>
        /// <param name="libraryManager">The library manager.</param>
        /// <param name="userManager">The user manager.</param>
        public LibraryChangedNotifierSaga(
            ILogger<LibraryChangedNotifierSaga> logger,
            ISessionManager sessionManager,
            ILibraryManager libraryManager,
            IUserManager userManager)
        {
            _logger = logger;
            _sessionManager = sessionManager;
            _libraryManager = libraryManager;
            _userManager = userManager;
        }

        /// <inheritdoc />
        public async Task Handle(ItemAddedEventArgs message)
        {
            if (!FilterItem(message.Item))
            {
                return;
            }

            await Data.LibraryChangedSyncLock.WaitAsync().ConfigureAwait(false);

            try
            {
                if (Data.LibraryUpdateTimer == null)
                {
                    Data.LibraryUpdateTimer = new Timer(
                        LibraryUpdateTimerCallback,
                        null,
                        LibraryUpdateDuration,
                        Timeout.Infinite);
                }
                else
                {
                    Data.LibraryUpdateTimer.Change(LibraryUpdateDuration, Timeout.Infinite);
                }

                if (message.Item.GetParent() is Folder parent)
                {
                    Data.FoldersAddedTo.Add(parent);
                }

                Data.ItemsAdded.Add(message.Item);
            }
            finally
            {
                Data.LibraryChangedSyncLock.Release();
            }
        }

        /// <inheritdoc />
        public async Task Handle(ItemChangedEventArgs message)
        {
            if (!FilterItem(message.Item))
            {
                return;
            }

            await Data.LibraryChangedSyncLock.WaitAsync().ConfigureAwait(false);

            try
            {
                if (Data.LibraryUpdateTimer == null)
                {
                    Data.LibraryUpdateTimer = new Timer(LibraryUpdateTimerCallback, null, LibraryUpdateDuration, Timeout.Infinite);
                }
                else
                {
                    Data.LibraryUpdateTimer.Change(LibraryUpdateDuration, Timeout.Infinite);
                }

                Data.ItemsUpdated.Add(message.Item);
            }
            finally
            {
                Data.LibraryChangedSyncLock.Release();
            }
        }

        /// <inheritdoc />
        public async Task Handle(ItemRemovedEventArgs message)
        {
            if (!FilterItem(message.Item))
            {
                return;
            }

            await Data.LibraryChangedSyncLock.WaitAsync().ConfigureAwait(false);

            try
            {
                if (Data.LibraryUpdateTimer == null)
                {
                    Data.LibraryUpdateTimer = new Timer(LibraryUpdateTimerCallback, null, LibraryUpdateDuration, Timeout.Infinite);
                }
                else
                {
                    Data.LibraryUpdateTimer.Change(LibraryUpdateDuration, Timeout.Infinite);
                }

                if (message.Parent is Folder parent)
                {
                    Data.FoldersRemovedFrom.Add(parent);
                }

                Data.ItemsRemoved.Add(message.Item);
            }
            finally
            {
                Data.LibraryChangedSyncLock.Release();
            }
        }

        /// <inheritdoc />
        protected override void CorrelateMessages(ICorrelationConfig<LibraryChangedSagaData> config)
        {
            // There should only be one instance of this saga, so all events share a saga.
            config.Correlate<ItemAddedEventArgs>(_ => true, _ => true);
            config.Correlate<ItemChangedEventArgs>(_ => true, _ => true);
            config.Correlate<ItemRemovedEventArgs>(_ => true, _ => true);
        }

        private static bool FilterItem(BaseItem item)
        {
            if (!item.IsFolder && !item.HasPathProtocol)
            {
                return false;
            }

            if (item is IItemByName && !(item is MusicArtist))
            {
                return false;
            }

            return item.SourceType == SourceType.Library;
        }

        private static IEnumerable<string> GetTopParentIds(IEnumerable<BaseItem> items, IReadOnlyCollection<Folder> allUserRootChildren)
        {
            var list = new List<string>();

            foreach (var item in items)
            {
                // If the physical root changed, return the user root
                if (item is AggregateFolder)
                {
                    continue;
                }

                foreach (var folder in allUserRootChildren)
                {
                    list.Add(folder.Id.ToString("N", CultureInfo.InvariantCulture));
                }
            }

            return list.Distinct(StringComparer.Ordinal);
        }

        private LibraryUpdateInfo GetLibraryUpdateInfo(
            IEnumerable<BaseItem> itemsAdded,
            IEnumerable<BaseItem> itemsUpdated,
            IEnumerable<BaseItem> itemsRemoved,
            IReadOnlyCollection<Folder> foldersAddedTo,
            IReadOnlyCollection<Folder> foldersRemovedFrom,
            Guid userId)
        {
            var user = _userManager.GetUserById(userId);

            var newAndRemoved = new List<BaseItem>();
            newAndRemoved.AddRange(foldersAddedTo);
            newAndRemoved.AddRange(foldersRemovedFrom);

            var allUserRootChildren = _libraryManager
                .GetUserRootFolder()
                .GetChildren(user, true)
                .OfType<Folder>()
                .ToList();

            return new LibraryUpdateInfo
            {
                ItemsAdded = itemsAdded
                    .SelectMany(i => TranslatePhysicalItemToUserLibrary(i, user))
                    .Select(i => i.Id.ToString("N", CultureInfo.InvariantCulture))
                    .Distinct()
                    .ToArray(),
                ItemsUpdated = itemsUpdated
                    .SelectMany(i => TranslatePhysicalItemToUserLibrary(i, user))
                    .Select(i => i.Id.ToString("N", CultureInfo.InvariantCulture))
                    .Distinct()
                    .ToArray(),
                ItemsRemoved = itemsRemoved
                    .SelectMany(i => TranslatePhysicalItemToUserLibrary(i, user, true))
                    .Select(i => i.Id.ToString("N", CultureInfo.InvariantCulture))
                    .Distinct()
                    .ToArray(),
                FoldersAddedTo = foldersAddedTo
                    .SelectMany(i => TranslatePhysicalItemToUserLibrary(i, user))
                    .Select(i => i.Id.ToString("N", CultureInfo.InvariantCulture))
                    .Distinct()
                    .ToArray(),
                FoldersRemovedFrom = foldersRemovedFrom
                    .SelectMany(i => TranslatePhysicalItemToUserLibrary(i, user))
                    .Select(i => i.Id.ToString("N", CultureInfo.InvariantCulture))
                    .Distinct()
                    .ToArray(),
                CollectionFolders = GetTopParentIds(newAndRemoved, allUserRootChildren).ToArray()
            };
        }

        private async void LibraryUpdateTimerCallback(object? state)
        {
            await Data.LibraryChangedSyncLock.WaitAsync().ConfigureAwait(false);

            try
            {
                // Remove dupes in case some were saved multiple times
                var foldersAddedTo = Data.FoldersAddedTo
                    .GroupBy(x => x.Id)
                    .Select(x => x.First())
                    .ToList();

                var foldersRemovedFrom = Data.FoldersRemovedFrom
                    .GroupBy(x => x.Id)
                    .Select(x => x.First())
                    .ToList();

                var itemsUpdated = Data.ItemsUpdated
                    .Where(i => !Data.ItemsAdded.Contains(i))
                    .GroupBy(x => x.Id)
                    .Select(x => x.First())
                    .ToList();

                await SendChangeNotifications(
                    Data.ItemsAdded.ToList(),
                    itemsUpdated,
                    Data.ItemsRemoved.ToList(),
                    foldersAddedTo,
                    foldersRemovedFrom,
                    CancellationToken.None).ConfigureAwait(false);

                MarkAsComplete();
            }
            finally
            {
                Data.LibraryChangedSyncLock.Release();
            }
        }

        private async Task SendChangeNotifications(
            IReadOnlyCollection<BaseItem> itemsAdded,
            IReadOnlyCollection<BaseItem> itemsUpdated,
            IReadOnlyCollection<BaseItem> itemsRemoved,
            IReadOnlyCollection<Folder> foldersAddedTo,
            IReadOnlyCollection<Folder> foldersRemovedFrom,
            CancellationToken cancellationToken)
        {
            var userIds = _sessionManager.Sessions
                .Select(i => i.UserId)
                .Where(i => !i.Equals(Guid.Empty))
                .Distinct()
                .ToArray();

            foreach (var userId in userIds)
            {
                LibraryUpdateInfo info;

                try
                {
                    info = GetLibraryUpdateInfo(itemsAdded, itemsUpdated, itemsRemoved, foldersAddedTo, foldersRemovedFrom, userId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in GetLibraryUpdateInfo");
                    return;
                }

                if (info.IsEmpty)
                {
                    continue;
                }

                try
                {
                    await _sessionManager.SendMessageToUserSessions(new List<Guid> { userId }, SessionMessageType.LibraryChanged, info, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error sending LibraryChanged message");
                }
            }
        }

        private IEnumerable<T> TranslatePhysicalItemToUserLibrary<T>(T item, User user, bool includeIfNotFound = false)
            where T : BaseItem
        {
            // TODO: Investigate changing return type to T?
            // If the physical root changed, return the user root
            if (item is AggregateFolder)
            {
                return _libraryManager.GetUserRootFolder() is T rootFolder
                    ? new[] { rootFolder }
                    : Array.Empty<T>();
            }

            // Return it only if it's in the user's library
            if (includeIfNotFound || item.IsVisibleStandalone(user))
            {
                return new[] { item };
            }

            return Array.Empty<T>();
        }
    }
}
