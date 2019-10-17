## OWASP Top 10 Security Risks ( Open Web Application Security Project)
    # Injection
    # Broken Authentication
    # Sensitive data exposure
    # XML External Entities (XXE)
    # Broken Access control
    # Security misconfigurations
    # Cross Site Scripting (XSS)
    # Insecure Deserialization
    # Using Components with known vulnerabilities
    # Insufficient logging and monitoring

## Injection
    - An injection of code happens when an attacker sends invalid data to the web application with 
       the intention to make it do something different from what the application was designed/programmed to do.
    
    # How to prevent SQL injections:
        - keeping it to a minimum of Packages and libraries installed.
        - security requirements your developers can utilize when designing and writing software.
        - use a safe API, which avoids the use of the interpreter.   
        - migrate to use Object Relational Mapping Tools (ORMs).
        - Use positive or “whitelist” server-side input validation.
        - escape special characters using the specific escape syntax for that interpreter.
        - Settings to limit data exposure in case of successful injection attacks.
        - Separation of data from the web application logic.

##  Broken Authentication
    - A broken authentication vulnerability can allow an attacker to use manual and/or automatic
         mediums to try to gain control over any account he/she wants in a system – or even worse – to gain complete control over the system.

    # Types of Vulnerabilities
        - Permits automated attacks such as credential stuffing.
        - Permits brute force or other automated attacks.
        - Permits default, weak, or well-known passwords.
        - Uses plain text, encrypted, or weakly hashed passwords.
        - Has missing or ineffective multi-factor authentication.
        - Exposes Session IDs in the URL (e.g., URL rewriting).
        - Does not rotate Session IDs after successful login.

    # prevent broken authentication vulnerabilities
        - Where possible, implement multi-factor authentication to prevent automated credential stuffing, brute force, and stolen credential re-use attacks. 
        - Do not ship or deploy with any default credentials, particularly for admin users.
        - Align password length, complexity and rotation policies with NIST 800-63 B’s.
        - Ensure registration, credential recovery.
        - Limit or increasingly delay failed login attempts.
        - Use a server-side, secure, built-in session manager that generates a new random session ID with high entropy after login.

##  Sensitive Data Exposure:
    - Sensitive data exposure is one of the most widespread vulnerabilities.
        It consists of compromising data that should have been protected.
        # Some sensitive data that requires protection:
            - Passwords
            - Credit card numbers
            - Credentials
            - Social Security Numbers
            - Health information
            - Personally Identifiable Information.
    # What Are the Risks:
        - An application encrypts credit card numbers in a database using automatic database encryption,
            However, this data is automatically decrypted when retrieved,
             allowing an SQL injection flaw to retrieve credit card numbers in clear text.
        - A site doesn’t use or enforce TLS for all pages or supports weak encryption,
            (attacker monitors network traffic, downgrades connections from HTTPS to HTTP, 
                intercepts requests, and steals the user’s session cookie)
        - The password database uses unsalted or simple hashes to store everyone’s passwords.

    # How to Prevent Data Exposure:
        - Classify data processed, stored, or transmitted by an application.
        - Identify which data is sensitive according to privacy laws, regulatory requirements, or business needs.
        - Apply controls as per the classification.
        - Don’t store sensitive data unnecessarily.
        - Make sure to encrypt all sensitive data at rest.
        - Ensure up-to-date and strong standard algorithms, protocols.
        - Encrypt all data in transit with secure protocols such as TLS .
        - Disable caching for responses that contain sensitive data.
        - Verify independently the effectiveness of configuration and settings.

## XML External Entities (XXE)
    - An XML External Entity attack is a type of attack against an application that parses XML input.
         This attack occurs when XML input containing a reference to an external entity 
         is processed by a weakly configured XML parser (Mainly based on Developer).

    # What are the Attack Vectors?
        - exploitation of vulnerable XML processors if malicious actors can upload XML.
        - include hostile content in an XML document.
        - exploitation of vulnerable code.
        - exploitation of vulnerable dependencies.
        - exploitation of vulnerable integrations.
    # prevent XML External Entity attacks: 
        - use less complex data formats such as JSON, and avoid serialization of sensitive data.
        - Patch or upgrade all XML processors and libraries.
        - Use dependency checkers.
        - Implement positive (“whitelisting”) server-side input validation.

## Broken Access Control
    - In website security, access control means to put a limit on what sections 
        or pages visitors can reach, depending on their needs.

    # What Are the Risks?
        - The application uses unverified data in a SQL call that is accessing account information.
                http://example.com/app/accountInfo?acct=notmyacct
        - An attacker simply force browses to target URLs. Admin rights are required for access to the admin page.

    # Reducing the Risks of Broken Access Control
        - Get rid of accounts you don’t need.
        - Audit your servers and websites – who is doing what, when, and why.
        - apply multi-factor authentication to all your access points.
        - Remove unnecessary services off your server.
        - production box should not be the place to develop, test, or push updates without testing.

    # prevent broken access control:
        - Implement access control mechanisms once and reuse them throughout the application, including minimizing CORS usage.
        - access controls should enforce record ownership user can create, read, update, or delete any record related to him only.
        - Disable web server directory listing and ensure file metadata.
        - Log access control failures.
        - Rate limit API and controller access to minimize the harm from automated attack tooling.
        - JWT tokens should be invalidated on the server after logout.

## Security Misconfigurations
    - Hackers are always looking for ways to penetrate websites, and security misconfigurations
         can be an easy way in. 

    # Example of Attack Scenarios: 
        - The application server comes with sample applications that are not removed from the production server.
        - Directory listing is not disabled on the server. An attacker discovers they can simply list directories.
        - The application server’s configuration allows detailed error messages, e.g. stack traces, to be returned to users.

    # prevent security misconfigurations:
        - Development, QA, and production environments should all be configured identically, with different credentials.
        - Remove or do not install unused features and frameworks.
        - update the configurations appropriate to all security notes.
        - segmented application architecture that provides effective and secure separation between components.
        - An automated process to verify the effectiveness of the configurations and settings in all environments.

##  Cross-Site Scripting (XSS)
    - is a widespread vulnerability that affects many web applications. XSS attacks consist of
        injecting malicious client-side scripts into a website and using the website 
        as a propagation method.
    - The danger behind XSS is that it allows an attacker to inject content into a website 
        and modify how it is displayed, forcing a victim’s browser to execute the code provided
         by the attacker while loading the page.    
    - XSS is present in about two-thirds of all applications.

    # Types of XSS:
        - Reflected XSS: The application or API includes unvalidated and unescaped user input
             as part of HTML output. A successful attack can allow the attacker to execute arbitrary HTML
              and JavaScript in the victim’s browser.
        - Stored XSS: The application or API stores unsanitized user input that is viewed at
             a later time by another user or an administrator. Stored XSS is often 
             considered high or critical risk.
        - DOM XSS: JavaScript frameworks, single-page applications, and APIs that dynamically include
             attacker-controllable data to a page are vulnerable to DOM XSS. Ideally, 
             the application would not send attacker-controllable data to unsafe JavaScript APIs.

    # Prevent XSS:
        - Using frameworks that automatically escape XSS by design.
        - Escaping untrusted HTTP request data based on the context in the HTML output.
        - Applying context-sensitive encoding.

## Insecure Deserialization:
    - The process of serialization is converting objects to byte strings.
    - The process of deserialization is converting byte strings to objects.

    # Prevent Insecure Deserializations:
        - Implementing integrity checks such as digital signatures.
        - Isolating and running code that deserializes in low privilege environments when possible.
        - Logging deserialization exceptions and failures.
        - Restricting or monitoring incoming and outgoing network connectivity from containers or servers that deserialize
        - Monitoring deserialization, alerting if a user deserializes constantly.

## Using Components with Known Vulnerabilities
    - These days, even simple websites such as personal blogs have a lot of dependencies.
    - Whatever the reason for running out-of-date software on your web application is,
        you can’t leave it unprotected. Both Sucuri and OWASP recommend virtual patching 
        for the cases where patching is not possible.

    # Vulnerable applications are usually outdated if:
        - You do not know the versions of all components you use.
        - The software is vulnerable, unsupported, or out of date.
        - You do not fix or upgrade the underlying platform, frameworks, and dependencies in a risk-based.
        - The software developers do not test the compatibility of updated, upgraded, or patched libraries.
        - You do not secure the components’ configurations.

    # Prevent Using Components with Known Vulnerabilities:
        - Remove all unnecessary dependencies.
        - Monitor sources like Common Vulnerabilities and Disclosures.
        - Obtain components only from official sources.
        - Get rid of components not actively maintained.


## Insufficient Logging and Monitoring 
    - Not having an efficient logging and monitoring process in place can increase 
        the chances of a website compromise.

    # How to Have Efficient Website Monitoring:
        - Keeping audit logs are vital to staying on top of any suspicious change to your website.

               






   # References:
   - https://blog.sucuri.net/2018/10/owasp-top-10-security-risks-part-ii.html
   - https://blog.sucuri.net/2019/01/owasp-top-10-security-risks-part-iv.html
   - https://blog.sucuri.net/2019/01/owasp-top-10-security-risks-part-v.html
   - https://blog.sucuri.net/2018/12/owasp-top-10-security-risks-part-iii.html   
   - https://blog.sucuri.net/2019/01/owasp-top-10-security-risks-part-V.html           
