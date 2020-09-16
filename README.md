# Azure-WVD-REST-API-Python
Using Azure REST API to query WVD infrastructure information.

```python
a = AzureWVDRequests("client_id", "client_secret",
                     "tenant_id", "subscription_id")

hostpool_dict, rg_list = a.get_hostpool_vms_rgs()

sessionhost_list, session_id_list, user_list = a.get_wvd_usersessions(hostpool_dict, rg_list)

active_sessions = a.get_active_sessions("hostpool", "sessionhost", "resource_group")

new_session_is_allowed = a.check_allow_new_sessionstatus("hostpool", "sessionhost", "resource_group")
```
