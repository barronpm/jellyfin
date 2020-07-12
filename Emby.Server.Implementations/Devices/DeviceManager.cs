using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Data.Entities;
using Jellyfin.Data.Enums;
using MediaBrowser.Controller.Devices;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Security;
using MediaBrowser.Model.Devices;
using MediaBrowser.Model.Events;
using MediaBrowser.Model.Querying;
using MediaBrowser.Model.Session;

namespace Emby.Server.Implementations.Devices
{
    /// <summary>
    /// Manages the storage and retrieval of devices and their capabilities.
    /// </summary>
    public class DeviceManager : IDeviceManager
    {
        private readonly IUserManager _userManager;
        private readonly IAuthenticationRepository _authRepo;
        private readonly IDictionary<string, ClientCapabilities> _capabilities;

        /// <summary>
        /// Initializes a new instance of the <see cref="DeviceManager"/> class.
        /// </summary>
        /// <param name="authRepo">The authentication repository.</param>
        /// <param name="userManager">The user manager.</param>
        public DeviceManager(IAuthenticationRepository authRepo, IUserManager userManager)
        {
            _userManager = userManager;
            _authRepo = authRepo;
            _capabilities = new ConcurrentDictionary<string, ClientCapabilities>(StringComparer.OrdinalIgnoreCase);
        }

        /// <inheritdoc />
        public event EventHandler<GenericEventArgs<Tuple<string, DeviceOptions>>> DeviceOptionsUpdated;

        /// <inheritdoc />
        public void SaveCapabilities(string deviceId, ClientCapabilities capabilities)
        {
            _capabilities[deviceId] = capabilities;
        }

        /// <inheritdoc />
        public void UpdateDeviceOptions(string deviceId, DeviceOptions options)
        {
            _authRepo.UpdateDeviceOptions(deviceId, options);

            DeviceOptionsUpdated?.Invoke(this, new GenericEventArgs<Tuple<string, DeviceOptions>>(new Tuple<string, DeviceOptions>(deviceId, options)));
        }

        /// <inheritdoc />
        public DeviceOptions GetDeviceOptions(string deviceId)
        {
            return _authRepo.GetDeviceOptions(deviceId);
        }

        /// <inheritdoc />
        public ClientCapabilities GetCapabilities(string id)
        {
            return _capabilities.TryGetValue(id, out var result) ? result : new ClientCapabilities();
        }

        /// <inheritdoc />
        public DeviceInfo GetDevice(string id)
        {
            var items = _authRepo.Get(new AuthenticationInfoQuery
            {
                DeviceId = id
            }).Items;

            return items == null || items.Count == 0 ? null : ToDeviceInfo(items[0]);
        }

        /// <inheritdoc />
        public QueryResult<DeviceInfo> GetDevices(DeviceQuery query)
        {
            IEnumerable<AuthenticationInfo> sessions = _authRepo.Get(new AuthenticationInfoQuery
            {
                // UserId = query.UserId
                HasUser = true
            }).Items;

            // TODO: DeviceQuery doesn't seem to be used from client. Not even Swagger.
            if (query.SupportsSync.HasValue)
            {
                var val = query.SupportsSync.Value;

                sessions = sessions.Where(i => GetCapabilities(i.DeviceId).SupportsSync == val);
            }

            if (!query.UserId.Equals(Guid.Empty))
            {
                var user = _userManager.GetUserById(query.UserId);

                sessions = sessions.Where(i => CanAccessDevice(user, i.DeviceId));
            }

            var array = sessions.Select(ToDeviceInfo).ToArray();

            return new QueryResult<DeviceInfo>(array);
        }

        /// <inheritdoc />
        public bool CanAccessDevice(User user, string deviceId)
        {
            if (user == null)
            {
                throw new ArgumentException("user not found");
            }

            if (string.IsNullOrEmpty(deviceId))
            {
                throw new ArgumentNullException(nameof(deviceId));
            }

            if (user.HasPermission(PermissionKind.EnableAllDevices) || user.HasPermission(PermissionKind.IsAdministrator))
            {
                return true;
            }

            if (!user.GetPreference(PreferenceKind.EnabledDevices).Contains(deviceId, StringComparer.OrdinalIgnoreCase))
            {
                var capabilities = GetCapabilities(deviceId);

                if (capabilities != null && capabilities.SupportsPersistentIdentifier)
                {
                    return false;
                }
            }

            return true;
        }

        private DeviceInfo ToDeviceInfo(AuthenticationInfo authInfo)
        {
            var caps = GetCapabilities(authInfo.DeviceId);

            return new DeviceInfo
            {
                AppName = authInfo.AppName,
                AppVersion = authInfo.AppVersion,
                Id = authInfo.DeviceId,
                LastUserId = authInfo.UserId,
                LastUserName = authInfo.UserName,
                Name = authInfo.DeviceName,
                DateLastActivity = authInfo.DateLastActivity,
                IconUrl = caps?.IconUrl
            };
        }
    }
}
