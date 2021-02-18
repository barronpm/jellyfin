using System.Collections.Generic;
using System.Threading;
using MediaBrowser.Controller.Entities;
using Rebus.Sagas;

namespace Jellyfin.Server.Implementations.Sagas
{
    /// <summary>
    /// Contains the data for the LibraryChangedNotifier saga.
    /// </summary>
    public class LibraryChangedSagaData : SagaData
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="LibraryChangedSagaData"/> class.
        /// </summary>
        public LibraryChangedSagaData()
        {
            FoldersAddedTo = new List<Folder>();
            FoldersRemovedFrom = new List<Folder>();
            ItemsAdded = new List<BaseItem>();
            ItemsUpdated = new List<BaseItem>();
            ItemsRemoved = new List<BaseItem>();
            LibraryChangedSyncLock = new SemaphoreSlim(1, 1);
        }

        /// <summary>
        /// Gets a collection containing the folders that have been added to.
        /// </summary>
        public ICollection<Folder> FoldersAddedTo { get; }

        /// <summary>
        /// Gets a collection containing the folders that have been removed from.
        /// </summary>
        public ICollection<Folder> FoldersRemovedFrom { get; }

        /// <summary>
        /// Gets a collection containing the items that have been added.
        /// </summary>
        public ICollection<BaseItem> ItemsAdded { get; }

        /// <summary>
        /// Gets a collection containing the items that have been updated.
        /// </summary>
        public ICollection<BaseItem> ItemsUpdated { get; }

        /// <summary>
        /// Gets a collection containing the items that have been removed.
        /// </summary>
        public ICollection<BaseItem> ItemsRemoved { get; }

        /// <summary>
        /// Gets a lock for library changes.
        /// </summary>
        public SemaphoreSlim LibraryChangedSyncLock { get; }

        /// <summary>
        /// Gets or sets the library update timer.
        /// </summary>
        public Timer? LibraryUpdateTimer { get; set; }
    }
}
