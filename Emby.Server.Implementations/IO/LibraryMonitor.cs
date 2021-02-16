#pragma warning disable CS1591

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Emby.Server.Implementations.Library;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Events.Library;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Configuration;
using MediaBrowser.Model.IO;
using Microsoft.Extensions.Logging;

namespace Emby.Server.Implementations.IO
{
    /// <summary>
    /// Manages the monitoring of library files.
    /// </summary>
    public class LibraryMonitor : ILibraryMonitor
    {
        private readonly ILogger<LibraryMonitor> _logger;
        private readonly ILibraryManager _libraryManager;
        private readonly IServerConfigurationManager _configurationManager;
        private readonly IFileSystem _fileSystem;

        /// <summary>
        /// The file system watchers.
        /// </summary>
        private readonly ConcurrentDictionary<string, FileSystemWatcher> _fileSystemWatchers = new (StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// The affected paths.
        /// </summary>
        private readonly List<FileRefresher> _activeRefreshers = new ();

        /// <summary>
        /// A dynamic list of paths that should be ignored.  Added to during our own file system modifications.
        /// </summary>
        private readonly ConcurrentDictionary<string, string> _tempIgnoredPaths = new (StringComparer.OrdinalIgnoreCase);

        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="LibraryMonitor"/> class.
        /// </summary>
        /// <param name="logger">The logger.</param>
        /// <param name="libraryManager">The library manager.</param>
        /// <param name="configurationManager">The configuration manager.</param>
        /// <param name="fileSystem">The file system.</param>
        public LibraryMonitor(
            ILogger<LibraryMonitor> logger,
            ILibraryManager libraryManager,
            IServerConfigurationManager configurationManager,
            IFileSystem fileSystem)
        {
            _libraryManager = libraryManager;
            _logger = logger;
            _configurationManager = configurationManager;
            _fileSystem = fileSystem;
        }

        /// <inheritdoc />
        public bool IsRunning { get; private set; }

        /// <inheritdoc />
        public bool IsMonitoringEnabled(BaseItem item, LibraryOptions options)
        {
            if (item is BasePluginFolder)
            {
                return false;
            }

            if (options != null)
            {
                return options.EnableRealtimeMonitor;
            }

            return false;
        }

        /// <inheritdoc />
        public void Start()
        {
            _libraryManager.ItemRemoved += OnLibraryManagerItemRemoved;

            var pathsToWatch = new List<string>();

            var paths = _libraryManager
                .RootFolder
                .Children
                .Where(item => IsMonitoringEnabled(item, _libraryManager.GetLibraryOptions(item)))
                .OfType<Folder>()
                .SelectMany(f => f.PhysicalLocations)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(i => i)
                .ToList();

            foreach (var path in paths)
            {
                if (!ContainsParentFolder(pathsToWatch, path))
                {
                    pathsToWatch.Add(path);
                }
            }

            foreach (var path in pathsToWatch)
            {
                StartWatchingPath(path);
            }

            IsRunning = true;
        }

        /// <inheritdoc />
        public void ReportFileSystemChangeBeginning(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException(nameof(path));
            }

            // Ignore changes until the filesystem change is complete.
            _tempIgnoredPaths[path] = path;
        }

        /// <inheritdoc />
        public async void ReportFileSystemChangeComplete(string path, bool refreshPath)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException(nameof(path));
            }

            // This is an arbitrary amount of time, but delay it because file system writes often trigger events long after the file was actually written to.
            // Seeing long delays in some situations, especially over the network, sometimes up to 45 seconds
            // But if we make this delay too high, we risk missing legitimate changes, such as user adding a new file, or hand-editing metadata
            await Task.Delay(45000).ConfigureAwait(false);

            _tempIgnoredPaths.TryRemove(path, out _);

            if (refreshPath)
            {
                try
                {
                    ReportFileSystemChanged(path);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in ReportFileSystemChanged for {Path}", path);
                }
            }
        }

        /// <summary>
        /// Handles the ItemRemoved event of the LibraryManager control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="ItemChangedEventArgs"/> instance containing the event data.</param>
        private void OnLibraryManagerItemRemoved(object sender, ItemChangedEventArgs e)
        {
            if (e.Parent is AggregateFolder)
            {
                StopWatchingPath(e.Item.Path);
            }
        }

        /// <summary>
        /// Examine a list of strings assumed to be file paths to see if it contains a parent of
        /// the provided path.
        /// </summary>
        /// <param name="lst">The LST.</param>
        /// <param name="path">The path.</param>
        /// <returns><c>true</c> if [contains parent folder] [the specified LST]; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">path</exception>
        private static bool ContainsParentFolder(IEnumerable<string> lst, string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException(nameof(path));
            }

            path = path.TrimEnd(Path.DirectorySeparatorChar);

            return lst.Any(str =>
            {
                // this should be a little quicker than examining each actual parent folder...
                var compare = str.TrimEnd(Path.DirectorySeparatorChar);

                return path.Equals(compare, StringComparison.OrdinalIgnoreCase) || (path.StartsWith(compare, StringComparison.OrdinalIgnoreCase) && path[compare.Length] == Path.DirectorySeparatorChar);
            });
        }

        /// <inheritdoc />
        public void StartWatchingPath(string path)
        {
            if (!Directory.Exists(path))
            {
                // Seeing a crash in the mono runtime due to an exception being thrown on a different thread
                _logger.LogInformation("Skipping realtime monitor for {Path} because the path does not exist", path);
                return;
            }

            // Already being watched
            if (_fileSystemWatchers.ContainsKey(path))
            {
                return;
            }

            // Creating a FileSystemWatcher over the LAN can take hundreds of milliseconds, so wrap it in a Task to do them all in parallel
            Task.Run(() =>
            {
                try
                {
                    var newWatcher = new FileSystemWatcher(path, "*")
                    {
                        IncludeSubdirectories = true,
                        InternalBufferSize = 65536,
                        NotifyFilter = NotifyFilters.CreationTime |
                                       NotifyFilters.DirectoryName |
                                       NotifyFilters.FileName |
                                       NotifyFilters.LastWrite |
                                       NotifyFilters.Size |
                                       NotifyFilters.Attributes
                    };

                    newWatcher.Created += OnWatcherChanged;
                    newWatcher.Deleted += OnWatcherChanged;
                    newWatcher.Renamed += OnWatcherChanged;
                    newWatcher.Changed += OnWatcherChanged;
                    newWatcher.Error += OnWatcherError;

                    if (_fileSystemWatchers.TryAdd(path, newWatcher))
                    {
                        newWatcher.EnableRaisingEvents = true;
                        _logger.LogInformation("Watching directory {Path}", path);
                    }
                    else
                    {
                        DisposeWatcher(newWatcher, false);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error watching path: {Path}", path);
                }
            });
        }

        /// <summary>
        /// Stops the watching path.
        /// </summary>
        /// <param name="path">The path.</param>
        public void StopWatchingPath(string path)
        {
            if (_fileSystemWatchers.TryGetValue(path, out var watcher))
            {
                DisposeWatcher(watcher, true);
            }
        }

        /// <summary>
        /// Disposes the watcher.
        /// </summary>
        private void DisposeWatcher(FileSystemWatcher watcher, bool removeFromList)
        {
            try
            {
                using (watcher)
                {
                    _logger.LogInformation("Stopping directory watching for path {Path}", watcher.Path);

                    watcher.Created -= OnWatcherChanged;
                    watcher.Deleted -= OnWatcherChanged;
                    watcher.Renamed -= OnWatcherChanged;
                    watcher.Changed -= OnWatcherChanged;
                    watcher.Error -= OnWatcherError;

                    watcher.EnableRaisingEvents = false;
                }
            }
            finally
            {
                if (removeFromList)
                {
                    _fileSystemWatchers.TryRemove(watcher.Path, out _);
                }
            }
        }

        /// <summary>
        /// Handles the Error event of the watcher control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="ErrorEventArgs" /> instance containing the event data.</param>
        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            var ex = e.GetException();
            var dw = (FileSystemWatcher)sender;

            _logger.LogError(ex, "Error in Directory watcher for: {Path}", dw.Path);

            DisposeWatcher(dw, true);
        }

        /// <summary>
        /// Handles the Changed event of the watcher control.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="FileSystemEventArgs" /> instance containing the event data.</param>
        private void OnWatcherChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                ReportFileSystemChanged(e.FullPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception in ReportFileSystemChanged. Path: {FullPath}", e.FullPath);
            }
        }

        /// <inheritdoc />
        public void ReportFileSystemChanged(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException(nameof(path));
            }

            var monitorPath = !IgnorePatterns.ShouldIgnore(path);

            // Ignore certain files
            var tempIgnorePaths = _tempIgnoredPaths.Keys.ToList();

            // If the parent of an ignored path has a change event, ignore that too
            if (tempIgnorePaths.Any(i =>
            {
                if (_fileSystem.AreEqual(i, path))
                {
                    _logger.LogDebug("Ignoring change to {Path}", path);
                    return true;
                }

                if (_fileSystem.ContainsSubPath(i, path))
                {
                    _logger.LogDebug("Ignoring change to {Path}", path);
                    return true;
                }

                // Go up a level
                var parent = Path.GetDirectoryName(i);
                if (!string.IsNullOrEmpty(parent) && _fileSystem.AreEqual(parent, path))
                {
                    _logger.LogDebug("Ignoring change to {Path}", path);
                    return true;
                }

                return false;
            }))
            {
                monitorPath = false;
            }

            if (monitorPath)
            {
                // Avoid implicitly captured closure
                CreateRefresher(path);
            }
        }

        private void CreateRefresher(string path)
        {
            var parentPath = Path.GetDirectoryName(path);

            lock (_activeRefreshers)
            {
                foreach (var refresher in _activeRefreshers)
                {
                    // Path is already being refreshed
                    if (_fileSystem.AreEqual(path, refresher.Path))
                    {
                        refresher.RestartTimer();
                        return;
                    }

                    // Parent folder is already being refreshed
                    if (_fileSystem.ContainsSubPath(refresher.Path, path))
                    {
                        refresher.AddPath(path);
                        return;
                    }

                    // New path is a parent
                    if (_fileSystem.ContainsSubPath(path, refresher.Path))
                    {
                        refresher.ResetPath(path, null);
                        return;
                    }

                    // They are siblings. Rebase the refresher to the parent folder.
                    if (string.Equals(parentPath, Path.GetDirectoryName(refresher.Path), StringComparison.Ordinal))
                    {
                        refresher.ResetPath(parentPath, path);
                        return;
                    }
                }

                var newRefresher = new FileRefresher(path, _configurationManager, _libraryManager, _logger);
                newRefresher.Completed += OnFileRefresherCompleted;
                _activeRefreshers.Add(newRefresher);
            }
        }

        private void OnFileRefresherCompleted(object sender, EventArgs e)
        {
            var refresher = (FileRefresher)sender;
            DisposeRefresher(refresher);
        }

        /// <summary>
        /// Stops this instance.
        /// </summary>
        public void Stop()
        {
            _libraryManager.ItemRemoved -= OnLibraryManagerItemRemoved;

            foreach (var watcher in _fileSystemWatchers.Values.ToList())
            {
                DisposeWatcher(watcher, false);
            }

            _fileSystemWatchers.Clear();
            DisposeRefreshers();

            IsRunning = false;
        }

        private void DisposeRefresher(FileRefresher refresher)
        {
            lock (_activeRefreshers)
            {
                refresher.Dispose();
                _activeRefreshers.Remove(refresher);
            }
        }

        private void DisposeRefreshers()
        {
            lock (_activeRefreshers)
            {
                foreach (var refresher in _activeRefreshers.ToList())
                {
                    refresher.Dispose();
                }

                _activeRefreshers.Clear();
            }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                Stop();
            }

            _disposed = true;
        }
    }
}
