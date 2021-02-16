using System.Threading.Tasks;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Events.Library;
using MediaBrowser.Controller.Library;
using Rebus.Handlers;

namespace Emby.Server.Implementations.IO
{
    /// <summary>
    /// A class that handles the monitoring of updated items.
    /// </summary>
    public class LibraryMonitorEventHandlers : IHandleMessages<ItemAddedEventArgs>
    {
        private readonly ILibraryManager _libraryManager;
        private readonly ILibraryMonitor _libraryMonitor;

        /// <summary>
        /// Initializes a new instance of the <see cref="LibraryMonitorEventHandlers"/> class.
        /// </summary>
        /// <param name="libraryManager">The library manager.</param>
        /// <param name="libraryMonitor">The library monitor.</param>
        public LibraryMonitorEventHandlers(ILibraryManager libraryManager, ILibraryMonitor libraryMonitor)
        {
            _libraryManager = libraryManager;
            _libraryMonitor = libraryMonitor;
        }

        /// <inheritdoc />
        public Task Handle(ItemAddedEventArgs message)
        {
            if (!_libraryMonitor.IsRunning || message.Parent is not AggregateFolder)
            {
                return Task.CompletedTask;
            }

            if (_libraryMonitor.IsMonitoringEnabled(message.Item, _libraryManager.GetLibraryOptions(message.Item)))
            {
                _libraryMonitor.StartWatchingPath(message.Item.Path);
            }

            return Task.CompletedTask;
        }
    }
}
