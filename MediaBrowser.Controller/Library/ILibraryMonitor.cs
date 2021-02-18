#pragma warning disable CS1591

using System;
using MediaBrowser.Controller.Entities;
using MediaBrowser.Model.Configuration;

namespace MediaBrowser.Controller.Library
{
    public interface ILibraryMonitor : IDisposable
    {
        /// <summary>
        /// Gets a value indicating whether or not monitoring is running.
        /// </summary>
        bool IsRunning { get; }

        /// <summary>
        /// Checks whether the provided item is monitored.
        /// </summary>
        /// <param name="item">The item.</param>
        /// <param name="options">The library options.</param>
        /// <returns>Returns a value indicating whether the provided item is monitored on disk.</returns>
        bool IsMonitoringEnabled(BaseItem item, LibraryOptions options);

        /// <summary>
        /// Starts this instance.
        /// </summary>
        void Start();

        /// <summary>
        /// Stops this instance.
        /// </summary>
        void Stop();

        /// <summary>
        /// Reports the file system change beginning.
        /// </summary>
        /// <param name="path">The path.</param>
        void ReportFileSystemChangeBeginning(string path);

        /// <summary>
        /// Reports the file system change complete.
        /// </summary>
        /// <param name="path">The path.</param>
        /// <param name="refreshPath">if set to <c>true</c> [refresh path].</param>
        void ReportFileSystemChangeComplete(string path, bool refreshPath);

        /// <summary>
        /// Reports the file system changed.
        /// </summary>
        /// <param name="path">The path.</param>
        void ReportFileSystemChanged(string path);

        /// <summary>
        /// Starts the watching path.
        /// </summary>
        /// <param name="path">The path.</param>
        void StartWatchingPath(string path);

        /// <summary>
        /// Stops the watching path.
        /// </summary>
        /// <param name="path">The path.</param>
        void StopWatchingPath(string path);
    }
}
