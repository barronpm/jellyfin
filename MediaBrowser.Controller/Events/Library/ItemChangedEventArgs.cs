using MediaBrowser.Controller.Entities;
using MediaBrowser.Controller.Library;

namespace MediaBrowser.Controller.Events.Library
{
    /// <summary>
    /// An event that occurs when an item is changed in a library.
    /// </summary>
    public class ItemChangedEventArgs
    {
        /// <summary>
        /// Gets or sets the item.
        /// </summary>
        public BaseItem Item { get; set; }

        /// <summary>
        /// Gets or sets the parent.
        /// </summary>
        public BaseItem Parent { get; set; }

        /// <summary>
        /// Gets or sets the item.
        /// </summary>
        /// <value>The item.</value>
        public ItemUpdateType UpdateReason { get; set; }
    }
}
