# Rate Limiter & Security API

## Overview

A PHP-based API protection system that secures webhooks from abuse and attacks. It features rate limiting, IP blacklisting, VPN/proxy detection, and detailed audit logging, ensuring safe and efficient API usage.

## Key Features

- **Rate Limiting**: Sliding window limits for each IP.
- **IP Blacklisting**: Blocks malicious IPs.
- **VPN/Proxy Detection**: Identifies and blocks proxy/VPN traffic.
- **Custom Request Headers**: Validates request headers for extra security.
- **Duplicate Requests Prevention**: Stops multiple identical requests.
- **Audit Logs**: Keeps a log of all activities for monitoring.
- **Anti Delete**: Cannot be removed
## Quick Setup

1. **Clone/download** this repo.
2. **Configure** the following:
   - API key (`your-api-key`) on line 282
   - Webhook URL (`your-webhook-here`) on line 283
   - Request method (`SIGMA` or other) on line 286

```php
$api_key = "your-api-key"; // replace with your api key
$webhook_url = "your-webhook-here"; // replace with your webhook URL
$request_custom = "SIGMA"; // replace with your custom request header
```

## Example Usage
- Send a custom request to the script with a valid API key, message, and webhook URL.
- The script will process the request, validate the rate limit, check for blacklisted IPs, and ensure the request method and headers are correct.
- Check ```Client-Example.go``` or ```Client-Example-Windows.bat``` or ```Client-Example_Unix.bat``` for usage examples

# License
This work is licensed under a
[Creative Commons Attribution 4.0 International License][cc-by].

[![CC BY 4.0][cc-by-image]][cc-by]

[cc-by]: http://creativecommons.org/licenses/by/4.0/
[cc-by-image]: https://i.creativecommons.org/l/by/4.0/88x31.png
[cc-by-shield]: https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg
