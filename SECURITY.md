Security Policy for Guard Core
===============================

Supported Versions
------------------

We currently provide security updates for the following versions of Guard Core:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Supported          |
| < 1.0   | Not supported      |

Reporting a Vulnerability
-------------------------

We take the security of Guard Core seriously. If you believe you've found a security vulnerability, please follow these steps:

1. **Do not disclose the vulnerability publicly** until it has been addressed by the maintainers.
2. **Report the vulnerability through GitHub's security advisory feature**:
   - Go to the [Security tab](https://github.com/Guard-Core/guard-core/security/advisories) of the Guard Core repository
   - Click on "New draft security advisory"
   - Fill in the details of the vulnerability
   - Submit the advisory

   Alternatively, you can report vulnerabilities through [GitHub's private vulnerability reporting feature](https://github.com/Guard-Core/guard-core/security/advisories/new).

3. Include the following information in your report:
   - A description of the vulnerability and its potential impact
   - Steps to reproduce the issue
   - Affected versions
   - Any potential mitigations or workarounds

The maintainers will acknowledge your report within 48 hours and provide a detailed response within 7 days, including the next steps in handling the vulnerability.

Security Best Practices
-----------------------

When using Guard Core in your applications, consider the following security best practices:

### Configuration Recommendations

1. **API Tokens**: Store your IPInfo token securely using environment variables or a secure secrets management system, not hardcoded in your application.

2. **Whitelist and Blacklist**: Regularly review and update your IP whitelists and blacklists.

3. **Rate Limiting**: Set appropriate rate limits based on your application's requirements to prevent abuse.

4. **Auto-Ban Settings**: Configure auto-ban thresholds and durations based on your threat model.

5. **Country Blocking**: Only block countries if necessary for compliance or security reasons.

6. **HTTPS Enforcement**: Always enable HTTPS enforcement in production environments.

7. **CORS Settings**: Configure CORS settings with the principle of least privilege, only allowing necessary origins, methods, and headers.

### Redis Security

If using Redis for distributed state management:

1. Enable Redis authentication with a strong password
2. Configure Redis to only listen on localhost or use a secure network
3. Use TLS/SSL for Redis connections in production
4. Regularly update your Redis instance to the latest stable version

### Logging and Monitoring

1. **Log Rotation**: Implement log rotation for security logs to prevent disk space issues
2. **Log Monitoring**: Regularly review security logs for suspicious activity
3. **Alerts**: Set up alerts for unusual patterns detected by Guard Core

### Dependency Management

1. Regularly update Guard Core and its dependencies to the latest versions
2. Use a dependency scanning tool to identify and address vulnerabilities in your dependency tree

Security Features
-----------------

Guard Core provides several security features to protect your applications:

- IP Whitelisting and Blacklisting
- User Agent Filtering
- Rate Limiting
- Automatic IP Banning
- Penetration Attempt Detection
- Country-based Access Control
- Cloud Provider IP Blocking

For detailed information on configuring these features, refer to the [documentation](https://guard-core.github.io/guard-core).

Threat Model
------------

Guard Core is designed to protect against common web application threats, including:

- Brute force attacks
- Distributed denial-of-service (DDoS) attacks
- Web scraping and data harvesting
- Reconnaissance from known malicious IPs
- Basic penetration testing attempts

Note that Guard Core is a defense-in-depth measure and should be used alongside other security controls such as proper authentication, authorization, input validation, and output encoding.

Security Updates
----------------

Security updates will be released as needed. We recommend subscribing to GitHub releases or regularly checking for updates to ensure you're using the most secure version.

Responsible Disclosure
----------------------

We follow responsible disclosure principles. If you report a vulnerability to us:

1. We will confirm receipt of your vulnerability report
2. We will provide an estimated timeline for a fix
3. We will notify you when the vulnerability is fixed
4. We will publicly acknowledge your responsible disclosure (unless you prefer to remain anonymous)

License
-------

Guard Core is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
