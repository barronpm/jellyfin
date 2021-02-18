#pragma warning disable CS1591

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Data.Events;
using MediaBrowser.Controller.Channels;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Plugins;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Session;

namespace Emby.Server.Implementations.EntryPoints
{
    public class LibraryChangedNotifier : IServerEntryPoint
    {
        private readonly ILibraryManager _libraryManager;
        private readonly IProviderManager _providerManager;
        private readonly ISessionManager _sessionManager;

        private readonly ConcurrentDictionary<Guid, DateTime> _lastProgressMessageTimes = new ConcurrentDictionary<Guid, DateTime>();

        public LibraryChangedNotifier(
            ILibraryManager libraryManager,
            ISessionManager sessionManager,
            IProviderManager providerManager)
        {
            _libraryManager = libraryManager;
            _sessionManager = sessionManager;
            _providerManager = providerManager;
        }

        /// <summary>
        /// Gets or sets the library update timer.
        /// </summary>
        /// <value>The library update timer.</value>
        private Timer LibraryUpdateTimer { get; set; }

        public Task RunAsync()
        {
            _providerManager.RefreshCompleted += OnProviderRefreshCompleted;
            _providerManager.RefreshStarted += OnProviderRefreshStarted;
            _providerManager.RefreshProgress += OnProviderRefreshProgress;

            return Task.CompletedTask;
        }

        private void OnProviderRefreshProgress(object sender, GenericEventArgs<Tuple<BaseItem, double>> e)
        {
            var item = e.Argument.Item1;

            if (!EnableRefreshMessage(item))
            {
                return;
            }

            var progress = e.Argument.Item2;

            if (_lastProgressMessageTimes.TryGetValue(item.Id, out var lastMessageSendTime))
            {
                if (progress > 0 && progress < 100 && (DateTime.UtcNow - lastMessageSendTime).TotalMilliseconds < 1000)
                {
                    return;
                }
            }

            _lastProgressMessageTimes.AddOrUpdate(item.Id, key => DateTime.UtcNow, (key, existing) => DateTime.UtcNow);

            var dict = new Dictionary<string, string>();
            dict["ItemId"] = item.Id.ToString("N", CultureInfo.InvariantCulture);
            dict["Progress"] = progress.ToString(CultureInfo.InvariantCulture);

            try
            {
                _sessionManager.SendMessageToAdminSessions(SessionMessageType.RefreshProgress, dict, CancellationToken.None);
            }
            catch
            {
            }

            var collectionFolders = _libraryManager.GetCollectionFolders(item).ToList();

            foreach (var collectionFolder in collectionFolders)
            {
                var collectionFolderDict = new Dictionary<string, string>
                {
                    ["ItemId"] = collectionFolder.Id.ToString("N", CultureInfo.InvariantCulture),
                    ["Progress"] = (collectionFolder.GetRefreshProgress() ?? 0).ToString(CultureInfo.InvariantCulture)
                };

                try
                {
                    _sessionManager.SendMessageToAdminSessions(SessionMessageType.RefreshProgress, collectionFolderDict, CancellationToken.None);
                }
                catch
                {
                }
            }
        }

        private void OnProviderRefreshStarted(object sender, GenericEventArgs<BaseItem> e)
        {
            OnProviderRefreshProgress(sender, new GenericEventArgs<Tuple<BaseItem, double>>(new Tuple<BaseItem, double>(e.Argument, 0)));
        }

        private void OnProviderRefreshCompleted(object sender, GenericEventArgs<BaseItem> e)
        {
            OnProviderRefreshProgress(sender, new GenericEventArgs<Tuple<BaseItem, double>>(new Tuple<BaseItem, double>(e.Argument, 100)));

            _lastProgressMessageTimes.TryRemove(e.Argument.Id, out DateTime removed);
        }

        private static bool EnableRefreshMessage(BaseItem item)
        {
            if (!(item is Folder folder))
            {
                return false;
            }

            if (folder.IsRoot)
            {
                return false;
            }

            if (folder is AggregateFolder || folder is UserRootFolder)
            {
                return false;
            }

            if (folder is UserView || folder is Channel)
            {
                return false;
            }

            if (!folder.IsTopParent)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="dispose"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool dispose)
        {
            if (dispose)
            {
                if (LibraryUpdateTimer != null)
                {
                    LibraryUpdateTimer.Dispose();
                    LibraryUpdateTimer = null;
                }

                _providerManager.RefreshCompleted -= OnProviderRefreshCompleted;
                _providerManager.RefreshStarted -= OnProviderRefreshStarted;
                _providerManager.RefreshProgress -= OnProviderRefreshProgress;
            }
        }
    }
}
