
# NetScaler CLI snippet

String Maps and Pattern sets can be made more specific or duplicated for handling multiple FQDN's. 


```
add audit messageaction LOG_MIGRATION_SCHEDULE INFORMATIONAL "\"logtype=MIGRATION_SCHEDULE_TRUE SYSTEM_TIME=\" + SYS.TIME + \" URL=\" + HTTP.REQ.URL.HTTP_URL_SAFE + \"\"" -logtoNewnslog YES
add policy stringmap SM_REDIRECTION_SCHEDULE
bind policy stringmap SM_REDIRECTION_SCHEDULE "/site/migration_url-1" "Thu, 04 Dec 2025 23:00:00 GMT"
bind policy stringmap SM_REDIRECTION_SCHEDULE "/site/migration_url-2" "Mon, 08 Dec 2025 10:00:00 GMT"
bind policy stringmap SM_REDIRECTION_SCHEDULE "/site/migration_url-3" "Wed, 10 Oct 2025 16:00:00 GMT"
add policy patset PS_SCHEDULE_REDIRECT_URLS
bind policy patset PS_SCHEDULE_REDIRECT_URLS "/site/migration_url-1"
bind policy patset PS_SCHEDULE_REDIRECT_URLS "/site/migration_url-2"
bind policy patset PS_SCHEDULE_REDIRECT_URLS "/site/migration_url-3"
add responder action RS_ACT_SCHEDULE_REDIRECT_URL redirect "\"https://new.domain.com\" + HTTP.REQ.URL" -responseStatusCode 302
add responder policy RS_POL_SCHEDULE_REDIRECT_URL "HTTP.REQ.HOSTNAME.SERVER.EQ(\"old.domain.com\")&&HTTP.REQ.URL.TO_LOWER.STARTSWITH_ANY(\"PS_SCHEDULE_REDIRECT_URLS\")&&HTTP.REQ.URL.TO_LOWER.HTTP_URL_SAFE.REGEX_SELECT(re!^\\/[a-zA-Z0-9-_]+\\/[a-zA-Z0-9-_]+!).MAP_STRING(\"SM_REDIRECTION_SCHEDULE\").TYPECAST_TIME_T.LE(SYS.TIME)" NOOP -logAction LOG_MIGRATION_SCHEDULE
```
