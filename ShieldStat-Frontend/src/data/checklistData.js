// All 12 security checklist sections from digital-defense.io
// Each item: { id, title, description }

export const CHECKLIST_SECTIONS = [
  {
    id: "authentication",
    label: "Authentication",
    icon: "lock",
    color: "#800080",
    colorClass: "purple",
    description:
      "Most reported data breaches are caused by the use of weak, default, or stolen passwords. Use long, strong, and unique passwords, manage them in a secure password manager, enable 2-factor authentication, keep on top of breaches, and take care while logging into your accounts.",
    items: [
      {
        id: "auth-1",
        title: "Use a Strong Password",
        level: "Essential",
        description:
          "If your password is too short, or contains dictionary words, places, or names, then it can be easily cracked through brute force or guessed by someone. The easiest way to make a strong password is by making it long (12+ characters) — consider using a 'passphrase' made up of many words. Alternatively, use a password generator to create a long, strong random password. Have a play with Security.org's How Secure Is My Password?, to get an idea of how quickly common passwords can be cracked. Read more about creating strong passwords: securityinabox.org.",
      },
      {
        id: "auth-2",
        title: "Don't Reuse Passwords",
        level: "Essential",
        description:
          "If someone were to reuse a password and one site they had an account with suffered a leak, then a criminal could easily gain unauthorized access to their other accounts. This is usually done through large-scale automated login requests, and it is called Credential Stuffing. Unfortunately, this is all too common, but it's simple to protect against — use a different password for each of your online accounts.",
      },
      {
        id: "auth-3",
        title: "Use a Secure Password Manager",
        level: "Essential",
        description:
          "For most people, it is going to be near-impossible to remember hundreds of strong and unique passwords. A password manager is an application that generates, stores, and auto-fills your login credentials for you. All your passwords will be encrypted against 1 master password (which you must remember, and it should be very strong). Most password managers have browser extensions and mobile apps, so whatever device you are on, your passwords can be auto-filled. A good all-rounder is Bitwarden, or see Recommended Password Managers.",
      },
      {
        id: "auth-4",
        title: "Avoid Sharing Passwords",
        level: "Essential",
        description:
          "While there may be times that you need to share access to an account with another person, you should generally avoid doing this because it makes it easier for the account to become compromised. If you absolutely do need to share a password — for example, when working on a team with a shared account — this should be done via features built into a password manager.",
      },
      {
        id: "auth-5",
        title: "Enable 2-Factor Authentication",
        level: "Essential",
        description:
          "2FA is where you must provide both something you know (a password) and something you have (such as a code on your phone) to log in. This means that if anyone has your password (e.g., through phishing, malware, or a data breach), they will not be able to log into your account. It's easy to get started, download an authenticator app onto your phone, and then go to your account security settings and follow the steps to enable 2FA. Next time you log in on a new device, you will be prompted for the code that is displayed in the app on your phone (it works without internet, and the code usually changes every 30 seconds).",
      },
      {
        id: "auth-6",
        title: "Keep Backup Codes Safe",
        level: "Essential",
        description:
          "When you enable multi-factor authentication, you will usually be given several codes that you can use if your 2FA method is lost, broken, or unavailable. Keep these codes somewhere safe to prevent loss or unauthorized access. You should store these on paper or in a safe place on disk (e.g., in offline storage or an encrypted file/drive). Don't store these in your password manager as 2FA sources and passwords should be kept separately.",
      },
      {
        id: "auth-7",
        title: "Sign Up for Breach Alerts",
        level: "Optional",
        description:
          "After a website suffers a significant data breach, the leaked data often ends up on the internet. Several websites collect these leaked records and allow you to search your email address to check if you are in any of their lists. Firefox Monitor, Have I Been Pwned, and DeHashed allow you to sign up for monitoring, where they will notify if your email address appears in any new data sets. It is useful to know as soon as possible when this happens so that you can change your passwords for the affected accounts. Have i been pwned also has domain-wide notification, where you can receive alerts if any email addresses under your entire domain appear (useful if you use aliases for anonymous forwarding).",
      },
      {
        id: "auth-8",
        title: "Shield your Password/PIN",
        level: "Optional",
        description:
          "When typing your password in public places, ensure you are not in direct line of sight of a CCTV camera and that no one can see over your shoulder. Cover your password or pin code while you type, and do not reveal any plain text passwords on your screen.",
      },
      {
        id: "auth-9",
        title: "Update Critical Passwords Periodically",
        level: "Optional",
        description:
          "Database leaks and breaches are common, and, likely, several of your passwords are already somewhere online. Occasionally updating passwords of security-critical accounts can help mitigate this. But providing that all your passwords are long, strong, and unique, there is no need to do this too often — annually should be sufficient. Enforcing mandatory password changes within organisations is no longer recommended, as it encourages colleagues to select weaker passwords.",
      },
      {
        id: "auth-10",
        title: "Don’t Save your Password in Browsers",
        level: "Optional",
        description:
          "Most modern browsers offer to save your credentials when you log into a site. Don’t allow this, as they are not always encrypted and could allow someone to gain access to your accounts. Instead, use a dedicated password manager to store (and auto-fill) your passwords.",
      },
      {
        id: "auth-11",
        title: "Avoid Logging In on Someone Else’s Device",
        level: "Optional",
        description:
          "Avoid logging in on other people's computers since you can't be sure their system is clean. Be especially cautious of public machines, as malware and tracking are more common here. Using someone else's device is especially dangerous with critical accounts like online banking. When using someone else's machine, ensure that you're in a private/incognito session (Use Ctrl+Shift+N/ Cmd+Shift+N). This will request the browser to not save your credentials, cookies, and browsing history.",
      },
      {
        id: "auth-12",
        title: "Avoid Password Hints",
        level: "Optional",
        description:
          "Some sites allow you to set password hints. Often, it is very easy to guess answers. In cases where password hints are mandatory, use random answers and record them in your password manager (Name of the first school: 6D-02-8B-!a-E8-8F-81).",
      },
      {
        id: "auth-13",
        title: "Never Answer Online Security Questions Truthfully",
        level: "Optional",
        description:
          "If a site asks security questions (such as place of birth, mother's maiden name, or first car, etc.), don't provide real answers. It is a trivial task for hackers to find out this information online or through social engineering. Instead, create a fictitious answer, and store it inside your password manager. Using real words is better than random characters, as explained here.",
      },
      {
        id: "auth-14",
        title: "Don’t Use a 4-digit PIN",
        level: "Optional",
        description:
          "Don’t use a short PIN to access your smartphone or computer. Instead, use a text password or a much longer PIN. Numeric passphrases are easy to crack (A 4-digit pin has 10,000 combinations, compared to 7.4 million for a 4-character alpha-numeric code).",
      },
      {
        id: "auth-15",
        title: "Avoid Using SMS for 2FA",
        level: "Optional",
        description:
          "When enabling multi-factor authentication, opt for app-based codes or a hardware token if supported. SMS is susceptible to several common threats, such as SIM-swapping and interception. There's also no guarantee of how securely your phone number will be stored or what else it will be used for. From a practical point of view, SMS will only work when you have a signal and can be slow. If a website or service requires the usage of an SMS number for recovery, consider purchasing a second pre-paid phone number only used for account recovery for these instances.",
      },
      {
        id: "auth-16",
        title: "Avoid Using your PM to Generate OTPs",
        level: "Advanced",
        description:
          "Many password managers are also able to generate 2FA codes. It is best not to use your primary password manager as your 2FA authenticator as well, since it would become a single point of failure if compromised. Instead, use a dedicated authenticator app on your phone or laptop.",
      },
      {
        id: "auth-17",
        title: "Avoid Face Unlock",
        level: "Advanced",
        description:
          "Most phones and laptops offer a facial recognition authentication feature, using the camera to compare a snapshot of your face with a stored hash. It may be very convenient, but there are numerous ways to fool it and gain access to the device through digital photos and reconstructions from CCTV footage. Unlike your password, there are likely photos of your face on the internet and videos recorded by surveillance cameras.",
      },
      {
        id: "auth-18",
        title: "Watch Out for Keyloggers",
        level: "Advanced",
        description:
          "A hardware keylogger is a physical device planted between your keyboard and the USB port, which intercepts all keystrokes and sometimes relays data to a remote server. It gives a hacker access to everything typed, including passwords. The best way to stay protected is just by checking your USB connection after your PC has been unattended. It is also possible for keyloggers to be planted inside the keyboard housing, so look for any signs that the case has been tampered with, and consider bringing your own keyboard to work. Data typed on a virtual keyboard, pasted from the clipboard, or auto-filled by a password manager can not be intercepted by a hardware keylogger.",
      },
      {
        id: "auth-19",
        title: "Consider a Hardware Token",
        level: "Advanced",
        description:
          "A U2F/FIDO2 security key is a USB (or NFC) device that you insert while logging in to an online service to verify your identity instead of entering a OTP from your authenticator. SoloKey and NitroKey are examples of such keys. They bring with them several security benefits. Since the browser communicates directly with the device, it cannot be fooled as to which host is requesting.",
      },
      {
        id: "auth-20",
        title: "Consider Offline Password Manager",
        level: "Advanced",
        description:
          "For increased security, an encrypted offline password manager will give you full control over your data. KeePass is a popular choice, with lots of plugins and community forks with additional compatibility and functionality. Popular clients include: KeePassXC (desktop), KeePassDX (Android) and StrongBox (iOS). The drawback being that it may be slightly less convenient for some, and it will be up to you to back it up and store it securely.",
      },
      {
        id: "auth-21",
        title: "Consider Unique Usernames",
        level: "Advanced",
        description:
          "Having different passwords for each account is a good first step, but if you also use a unique username, email, or phone number to log in, then it will be significantly harder for anyone trying to gain unauthorised access. The easiest method for multiple emails, is using auto-generated aliases for anonymous mail forwarding. This is where [anything]@yourdomain.com will arrive in your inbox, allowing you to use a different email for each account (see Mail Alias Providers). Usernames are easier since you can use your password manager to generate, store, and auto-fill these. Virtual phone numbers can be generated through your VOIP provider.",
      },
    ],
  },
  {
    id: "web-browsing",
    label: "Web Browsing",
    icon: "travel_explore",
    color: "#0ea5e9",
    colorClass: "sky",
    description:
      "Most websites use some form of tracking, often to gain insight into users' behaviour and preferences. This data can be incredibly detailed and valuable to corporations, governments, and thieves. Take steps to minimize tracking and improve your privacy while browsing.",
    items: [
      {
        id: "web-1",
        title: "Block Ads",
        level: "Essential",
        description:
          "Using an ad-blocker can help improve your privacy, by blocking the trackers that ads implement. uBlock Origin is a very efficient and open source browser addon, developed by Raymond Hill. When 3rd-party ads are displayed on a webpage, they have the ability to track you, gathering personal information about you and your habits, which can then be sold, or used to show you more targeted ads, and some ads are plain malicious or fake. Blocking ads also makes pages load faster, uses less data and provides a less cluttered experience.",
      },
      {
        id: "web-2",
        title: "Use a Privacy-Respecting Browser",
        level: "Essential",
        description:
          "Firefox (with a few tweaks) and Brave are secure, private-respecting browsers. Both are fast, open source, user-friendly and available on all major operating systems. Your browser has access to everything that you do online, so if possible, avoid Google Chrome, Edge and Safari as (without correct configuration) all three of them, collect usage data, call home and allow for invasive tracking. Firefox requires a few changes to achieve optimal security, for example - arkenfox or 12byte's user.js configs. See more: Privacy Browsers.",
      },
      {
        id: "web-3",
        title: "Use a Private Search Engine",
        level: "Essential",
        description:
          "Using a privacy-preserving, non-tracking search engine, will reduce risk that your search terms are not logged, or used against you. Consider DuckDuckGo, or Qwant. Google implements some incredibly invasive tracking policies, and have a history of displaying biased search results. Therefore Google, along with Bing, Baidu, Yahoo and Yandex are incompatible with anyone looking to protect their privacy. It is recommended to update your browsers default search to a privacy-respecting search engine.",
      },
      {
        id: "web-4",
        title: "Remove Unnecessary Browser Addons",
        level: "Essential",
        description:
          "Extensions are able to see, log or modify anything you do in the browser, and some innocent looking browser apps, have malicious intentions. Websites can see which extensions you have installed, and may use this to enhance your fingerprint, to more accurately identify/ track you. Both Firefox and Chrome web stores allow you to check what permissions/access rights an extension requires before you install it. Check the reviews. Only install extensions you really need, and removed those which you haven't used in a while.",
      },
      {
        id: "web-5",
        title: "Keep Browser Up-to-date",
        level: "Essential",
        description:
          "Browser vulnerabilities are constantly being discovered and patched, so it’s important to keep it up to date, to avoid a zero-day exploit. You can see which browser version you're using here, or follow this guide for instructions on how to update. Some browsers will auto-update to the latest stable version.",
      },
      {
        id: "web-6",
        title: "Check for HTTPS",
        level: "Essential",
        description:
          "If you enter information on a non-HTTPS website, this data is transported unencrypted and can therefore be read by anyone who intercepts it. Do not enter any data on a non-HTTPS website, but also do not let the green padlock give you a false sense of security, just because a website has SSL certificate, does not mean that it is legitimate or trustworthy. HTTPS-Everywhere (developed by the EFF) used to be a browser extension/addon that automatically enabled HTTPS on websites, but as of 2022 is now deprecated. In their announcement article the EFF explains that most browsers now integrate such protections. Additionally, it provides instructions for Firefox, Chrome, Edge and Safari browsers on how to enable their HTTPS secure protections.",
      },
      {
        id: "web-7",
        title: "Use DNS-over-HTTPS",
        level: "Essential",
        description:
          "Traditional DNS makes requests in plain text for everyone to see. It allows for eavesdropping and manipulation of DNS data through man-in-the-middle attacks. Whereas DNS-over-HTTPS performs DNS resolution via the HTTPS protocol, meaning data between you and your DNS resolver is encrypted. A popular option is CloudFlare's 1.1.1.1, or compare providers- it is simple to enable in-browser. Note that DoH comes with its own issues, mostly preventing web filtering.",
      },
      {
        id: "web-8",
        title: "Multi-Session Containers",
        level: "Essential",
        description:
          "Compartmentalisation is really important to keep different aspects of your browsing separate. For example, using different profiles for work, general browsing, social media, online shopping etc will reduce the number associations that data brokers can link back to you. One option is to make use of Firefox Containers which is designed exactly for this purpose. Alternatively, you could use different browsers for different tasks (Brave, Firefox, Tor etc).",
      },
      {
        id: "web-9",
        title: "Use Incognito",
        level: "Essential",
        description:
          "When using someone else's machine, ensure that you're in a private/ incognito session. This will prevent browser history, cookies and some data being saved, but is not fool-proof- you can still be tracked.",
      },
      {
        id: "web-10",
        title: "Understand Your Browser Fingerprint",
        level: "Essential",
        description:
          "Browser Fingerprinting is an incredibly accurate method of tracking, where a website identifies you based on your device information. You can view your fingerprint at amiunique.org- The aim is to be as un-unique as possible.",
      },
      {
        id: "web-11",
        title: "Manage Cookies",
        level: "Essential",
        description:
          "Clearing cookies regularly is one step you can take to help reduce websites from tracking you. Cookies may also store your session token, which if captured, would allow someone to access your accounts without credentials. To mitigate this you should clear cookies often.",
      },
      {
        id: "web-12",
        title: "Block Third-Party Cookies",
        level: "Essential",
        description:
          "Third-party cookies placed on your device by a website other than the one you’re visiting. This poses a privacy risk, as a 3rd entity can collect data from your current session. This guide explains how you can disable 3rd-party cookies, and you can check here ensure this worked.",
      },
      {
        id: "web-13",
        title: "Block Third-Party Trackers",
        level: "Essential",
        description:
          "Blocking trackers will help to stop websites, advertisers, analytics and more from tracking you in the background. Privacy Badger, DuckDuckGo Privacy Essentials, uBlock Origin and uMatrix (advanced) are all very effective, open source tracker-blockers available for all major browsers.",
      },
      {
        id: "web-14",
        title: "Beware of Redirects",
        level: "Optional",
        description:
          "While some redirects are harmless, others, such as Unvalidated redirects are used in phishing attacks, it can make a malicious link seem legitimate. If you are unsure about a redirect URL, you can check where it forwards to with a tool like RedirectDetective.",
      },
      {
        id: "web-15",
        title: "Do Not Sign Into Your Browser",
        level: "Optional",
        description:
          "Many browsers allow you to sign in, in order to sync history, bookmarks and other browsing data across devices. However this not only allows for further data collection, but also increases attack surface through providing another avenue for a malicious actor to get hold of personal information.",
      },
      {
        id: "web-16",
        title: "Disallow Prediction Services",
        level: "Optional",
        description:
          "Some browsers allow for prediction services, where you receive real-time search results or URL auto-fill. If this is enabled then data is sent to Google (or your default search engine) with every keypress, rather than when you hit enter.",
      },
      {
        id: "web-17",
        title: "Avoid G Translate for Webpages",
        level: "Optional",
        description:
          "When you visit a web page written in a foreign language, you may be prompted to install the Google Translate extension. Be aware that Google collects all data (including input fields), along with details of the current user. Instead use a translation service that is not linked to your browser.",
      },
      {
        id: "web-18",
        title: "Disable Web Notifications",
        level: "Optional",
        description:
          "Browser push notifications are a common method for criminals to encourage you to click their link, since it is easy to spoof the source. Be aware of this, and for instructions on disabling browser notifications, see this article.",
      },
      {
        id: "web-19",
        title: "Disable Automatic Downloads",
        level: "Optional",
        description:
          "Drive-by downloads is a common method of getting harmful files onto a users device. This can be mitigated by disabling auto file downloads, and be cautious of websites which prompt you to download files unexpectedly.",
      },
      {
        id: "web-20",
        title: "Disallow Access to Sensors",
        level: "Optional",
        description:
          "Mobile websites can tap into your device sensors without asking. If you grant these permissions to your browser once, then all websites are able to use these capabilities, without permission or notification.",
      },
      {
        id: "web-21",
        title: "Disallow Location",
        level: "Optional",
        description:
          "Location Services lets sites ask for your physical location to improve your experience. This should be disabled in settings. Note that there are still other methods of determining your approximate location.",
      },
      {
        id: "web-22",
        title: "Disallow Camera/ Microphone access",
        level: "Optional",
        description:
          "Check browser settings to ensure that no websites are granted access to webcam or microphone. It may also be beneficial to use physical protection such as a webcam cover and microphone blocker.",
      },
      {
        id: "web-23",
        title: "Disable Browser Password Saves",
        level: "Optional",
        description:
          "Do not allow your browser to store usernames and passwords. These can be easily viewed or accessed. Instead use a password manager.",
      },
      {
        id: "web-24",
        title: "Disable Browser Autofill",
        level: "Optional",
        description:
          "Turn off autofill for any confidential or personal details. This feature can be harmful if your browser is compromised in any way. Instead, consider using your password manager's Notes feature.",
      },
      {
        id: "web-25",
        title: "Protect from Exfil Attack",
        level: "Optional",
        description:
          "The CSS Exfiltrate attack is a method where credentials and other sensitive details can be snagged with just pure CSS. You can stay protected, with the CSS Exfil Protection plugin.",
      },
      {
        id: "web-26",
        title: "Deactivate ActiveX",
        level: "Optional",
        description:
          "ActiveX is a browser extension API that built into Microsoft IE, and enabled by default. It's not commonly used anymore, but since it gives plugins intimate access rights, and can be dangerous, therefore you should disable it.",
      },
      {
        id: "web-27",
        title: "Disable WebRTC",
        level: "Optional",
        description:
          "WebRTC allows high-quality audio/video communication and peer-to-peer file-sharing straight from the browser. However it can pose as a privacy leak. To learn more, check out this guide.",
      },
      {
        id: "web-28",
        title: "Spoof HTML5 Canvas Sig",
        level: "Optional",
        description:
          "Canvas Fingerprinting allows websites to identify and track users very accurately. You can use the Canvas-Fingerprint-Blocker extension to spoof your fingerprint or use Tor.",
      },
      {
        id: "web-29",
        title: "Spoof User Agent",
        level: "Optional",
        description:
          "The user agent tells the website what device, browser and version you are using. Switching user agent periodically is one small step you can take to become less unique.",
      },
      {
        id: "web-30",
        title: "Disregard DNT",
        level: "Optional",
        description:
          "Enabling Do Not Track has very limited impact, since many websites do not respect or follow this. Since it is rarely used, it may also add to your signature, making you more unique.",
      },
      {
        id: "web-31",
        title: "Prevent HSTS Tracking",
        level: "Optional",
        description:
          "HSTS was designed to help secure websites, but privacy concerns have been raised as it allowed site operators to plant super-cookies. It can be disabled by visiting chrome://net-internals/#hsts in Chromium-based browsers.",
      },
      {
        id: "web-32",
        title: "Prevent Automatic Browser Connections",
        level: "Optional",
        description:
          "Even when you are not using your browser, it may call home to report on usage activity, analytics and diagnostics. You may wish to disable some of this, which can be done through the settings.",
      },
      {
        id: "web-33",
        title: "Enable 1st-Party Isolation",
        level: "Optional",
        description:
          "First Party Isolation means that all identifier sources and browser state are scoped using the URL bar domain, this can greatly reduce tracking.",
      },
      {
        id: "web-34",
        title: "Strip Tracking Params from URLs",
        level: "Advanced",
        description:
          "Websites often append additional GET parameters to URLs that you click, to identify information like source/referrer. You can sanitize manually, or use an extension like ClearURLs to strip tracking data from URLs automatically.",
      },
      {
        id: "web-35",
        title: "First Launch Security",
        level: "Advanced",
        description:
          "After installing a web browser, the first time you launch it (prior to configuring its privacy settings), most browsers will call home. Therefore, after installing a browser, you should first disable your internet connection, then configure privacy options before reenabling your internet connectivity.",
      },
      {
        id: "web-36",
        title: "Use The Tor Browser",
        level: "Advanced",
        description:
          "The Tor Project provides a browser that encrypts and routes your traffic through multiple nodes, keeping users safe from interception and tracking. The main drawbacks are speed and user experience.",
      },
      {
        id: "web-37",
        title: "Disable JavaScript",
        level: "Advanced",
        description:
          "Many modern web apps are JavaScript-based, so disabling it will greatly decrease your browsing experience. But if you really want to go all out, then it will really reduce your attack surface.",
      },
    ],
  },
  {
    id: "email",
    label: "Email",
    icon: "email",
    color: "#800080",
    colorClass: "purple",
    description:
      "Email is still a fundamental part of daily life, yet is fundamentally insecure by design. Email-related fraud is on the rise. If a hacker gets access to your emails, it provides a gateway for your other accounts to be compromised through password resets.",
    items: [
      {
        id: "email-1",
        title: "Have more than one email address",
        level: "Essential",
        description:
          "Consider using a different email address for security-critical communications from trivial mail such as newsletters. This compartmentalization could reduce the amount of damage caused by a data breach, and also make it easier to recover a compromised account.",
      },
      {
        id: "email-2",
        title: "Keep Email Address Private",
        level: "Essential",
        description:
          "Do not share your primary email publicly, as mail addresses are often the starting point for most phishing attacks.",
      },
      {
        id: "email-3",
        title: "Keep your Account Secure",
        level: "Essential",
        description:
          "Use a long and unique password, enable 2FA and be careful while logging in. Your email account provides an easy entry point to all your other online accounts for an attacker.",
      },
      {
        id: "email-4",
        title: "Disable Automatic Loading of Remote Content",
        level: "Essential",
        description:
          "Email messages can contain remote content such as images or stylesheets, often automatically loaded from the server. You should disable this, as it exposes your IP address and device information, and is often used for tracking. For more info, see this article.",
      },
      {
        id: "email-5",
        title: "Use Plaintext",
        level: "Optional",
        description:
          "There are two main types of emails on the internet: plaintext and HTML. The former is strongly preferred for privacy & security as HTML messages often include identifiers in links and inline images, which can collect usage and personal data. There's also numerous risks of remote code execution targeting the HTML parser of your mail client, which cannot be exploited if you are using plaintext. For more info, as well as setup instructions for your mail provider, see UsePlaintext.email.",
      },
      {
        id: "email-6",
        title: "Don’t connect third-party apps to your email account",
        level: "Optional",
        description:
          "If you give a third-party app or plug-in full access to your inbox, they effectively have full unhindered access to all your emails and their contents, which poses significant security and privacy risks.",
      },
      {
        id: "email-7",
        title: "Don't Share Sensitive Data via Email",
        level: "Optional",
        description:
          "Emails are very easily intercepted. Furthermore, you can’t be sure of how secure your recipient's environment is. Therefore, emails cannot be considered safe for exchanging confidential information, unless it is encrypted.",
      },
      {
        id: "email-8",
        title: "Consider Switching to a Secure Mail Provider",
        level: "Optional",
        description:
          "Secure and reputable email providers such as Forward Email, ProtonMail, and Tutanota allow for end-to-end encryption, full privacy as well as more security-focused features. Unlike typical email providers, your mailbox cannot be read by anyone but you, since all messages are encrypted.",
      },
      {
        id: "email-9",
        title: "Use Smart Key",
        level: "Advanced",
        description:
          "OpenPGP does not support Forward secrecy, which means if either your or the recipient's private key is ever stolen, all previous messages encrypted with it will be exposed. Therefore, you should take great care to keep your private keys safe. One method of doing so, is to use a USB Smart Key to sign or decrypt messages, allowing you to do so without your private key leaving the USB device.",
      },
      {
        id: "email-10",
        title: "Use Aliasing / Anonymous Forwarding",
        level: "Advanced",
        description:
          "Email aliasing allows messages to be sent to [anything]@my-domain.com and still land in your primary inbox. Effectively allowing you to use a different, unique email address for each service you sign up for. This means if you start receiving spam, you can block that alias and determine which company leaked your email address.",
      },
      {
        id: "email-11",
        title: "Subaddressing",
        level: "Optional",
        description:
          "An alternative to aliasing is subaddressing, where anything after the + symbol is omitted during mail delivery. This enables you to keep track of who shared/ leaked your email address, but unlike aliasing, it will not protect against your real address being revealed.",
      },
      {
        id: "email-12",
        title: "Use a Custom Domain",
        level: "Advanced",
        description:
          "Using a custom domain means that you are not dependent on the address assigned by your mail provider. So you can easily switch providers in the future and do not need to worry about a service being discontinued.",
      },
      {
        id: "email-13",
        title: "Sync with a client for backup",
        level: "Advanced",
        description:
          "To avoid losing temporary or permanent access to your emails during an unplanned event (such as an outage or account lock), Thunderbird can sync/ backup messages from multiple accounts via IMAP and store locally on your primary device.",
      },
      {
        id: "email-14",
        title: "Be Careful with Mail Signatures",
        level: "Advanced",
        description:
          "You do not know how secure of an email environment the recipient of your message may have. There are several extensions that automatically crawl messages, and create a detailed database of contact information based upon email signatures.",
      },
      {
        id: "email-15",
        title: "Be Careful with Auto-Replies",
        level: "Advanced",
        description:
          "Out-of-office automatic replies are very useful for informing people there will be a delay in replying, but all too often people reveal too much information- which can be used in social engineering and targeted attacks.",
      },
      {
        id: "email-16",
        title: "Choose the Right Mail Protocol",
        level: "Advanced",
        description:
          "Do not use outdated protocols (below IMAPv4 or POPv3), both have known vulnerabilities and out-dated security.",
      },
      {
        id: "email-17",
        title: "Self-Hosting",
        level: "Advanced",
        description:
          "Self-hosting your own mail server is not recommended for non-advanced users, since correctly securing it is critical yet requires strong networking knowledge.",
      },
      {
        id: "email-18",
        title: "Always use TLS Ports",
        level: "Advanced",
        description:
          "There are SSL options for POP3, IMAP, and SMTP as standard TCP/IP ports. They are easy to use, and widely supported so should always be used instead of plaintext email ports.",
      },
      {
        id: "email-19",
        title: "DNS Availability",
        level: "Advanced",
        description:
          "For self-hosted mail servers, to prevent DNS problems impacting availability- use at least 2 MX records, with secondary and tertiary MX records for redundancy when the primary MX record fails.",
      },
      {
        id: "email-20",
        title: "Prevent DDoS and Brute Force Attacks",
        level: "Advanced",
        description:
          "For self-hosted mail servers (specifically SMTP), limit your total number of simultaneous connections, and maximum connection rate to reduce the impact of attempted bot attacks.",
      },
      {
        id: "email-21",
        title: "Maintain IP Blacklist",
        level: "Advanced",
        description:
          "For self-hosted mail servers, you can improve spam filters and harden security, through maintaining an up-to-date local IP blacklist and a spam URI realtime block lists to filter out malicious hyperlinks.",
      },
    ],
  },
  {
    id: "messaging",
    label: "Messaging",
    icon: "chat",
    color: "#10b981",
    colorClass: "emerald",
    description:
      "Secure messaging apps provide end-to-end encryption, meaning only you and your recipient can read the messages. This section covers best practices for secure and private communication.",
    items: [
      {
        id: "msg-1",
        title: "Only Use Fully End-to-End Encrypted Messengers",
        level: "Essential",
        description:
          "End-to-end encryption is a system of communication where messages are encrypted on your device and not decrypted until they reach the intended recipient. This ensures that any actor who intercepts traffic cannot read the message contents, nor can anybody with access to the central servers where data is stored.",
      },
      {
        id: "msg-2",
        title: "Use only Open Source Messaging Platforms",
        level: "Essential",
        description:
          "If code is open source then it can be independently examined and audited by anyone qualified to do so, to ensure that there are no backdoors, vulnerabilities, or other security issues.",
      },
      {
        id: "msg-3",
        title: "Use a \"Trustworthy\" Messaging Platform",
        level: "Essential",
        description:
          "When selecting an encrypted messaging app, ensure it's fully open source, stable, actively maintained, and ideally backed by reputable developers.",
      },
      {
        id: "msg-4",
        title: "Check Security Settings",
        level: "Essential",
        description:
          "Enable security settings, including contact verification, security notifications, and encryption. Disable optional non-security features such as read receipt, last online, and typing notification.",
      },
      {
        id: "msg-5",
        title: "Ensure your Recipients Environment is Secure",
        level: "Essential",
        description:
          "Your conversation can only be as secure as the weakest link. Often the easiest way to infiltrate a communications channel is to target the individual or node with the least protection.",
      },
      {
        id: "msg-6",
        title: "Disable Cloud Services",
        level: "Essential",
        description:
          "Some mobile messaging apps offer a web or desktop companion. This not only increases attack surface but it has been linked to several critical security issues, and should therefore be avoided, if possible.",
      },
      {
        id: "msg-7",
        title: "Secure Group Chats",
        level: "Essential",
        description:
          "The risk of compromise rises exponentially, the more participants are in a group, as the attack surface increases. Periodically check that all participants are legitimate.",
      },
      {
        id: "msg-8",
        title: "Create a Safe Environment for Communication",
        level: "Essential",
        description:
          "There are several stages where your digital communications could be monitored or intercepted. This includes: your or your participants' device, your ISP, national gateway or government logging, the messaging provider, the servers.",
      },
      {
        id: "msg-9",
        title: "Agree on a Communication Plan",
        level: "Optional",
        description:
          "In certain situations, it may be worth making a communication plan. This should include primary and backup methods of securely getting in hold with each other.",
      },
      {
        id: "msg-10",
        title: "Strip Meta-Data from Media",
        level: "Optional",
        description:
          "Metadata is \"Data about Data\" or additional information attached to a file or transaction. When you send a photo, audio recording, video, or document you may be revealing more than you intended to.",
      },
      {
        id: "msg-11",
        title: "Defang URLs",
        level: "Optional",
        description:
          "Sending links via various services can unintentionally expose your personal information. This is because, when a thumbnail or preview is generated- it happens on the client-side.",
      },
      {
        id: "msg-12",
        title: "Verify your Recipient",
        level: "Optional",
        description:
          "Always ensure you are talking to the intended recipient, and that they have not been compromised. One method for doing so is to use an app which supports contact verification.",
      },
      {
        id: "msg-13",
        title: "Enable Ephemeral Messages",
        level: "Optional",
        description:
          "Self-destructing messages is a feature that causes your messages to automatically delete after a set amount of time. This means that if your device is lost, stolen, or seized, an adversary will only have access to the most recent communications.",
      },
      {
        id: "msg-14",
        title: "Avoid SMS",
        level: "Optional",
        description:
          "SMS may be convenient, but it's not secure. It is susceptible to threats such as interception, sim swapping, manipulation, and malware.",
      },
      {
        id: "msg-15",
        title: "Watch out for Trackers",
        level: "Optional",
        description:
          "Be wary of messaging applications with trackers, as the detailed usage statistics they collect are often very invasive, and can sometimes reveal your identity as well as personal information that you would otherwise not intend to share.",
      },
      {
        id: "msg-16",
        title: "Consider Jurisdiction",
        level: "Advanced",
        description:
          "The jurisdictions where the organisation is based, and data is hosted should also be taken into account.",
      },
      {
        id: "msg-17",
        title: "Use an Anonymous Platform",
        level: "Advanced",
        description:
          "If you believe you may be targeted, you should opt for an anonymous messaging platform that does not require a phone number, or any other personally identifiable information to sign up or use.",
      },
      {
        id: "msg-18",
        title: "Ensure Forward Secrecy is Supported",
        level: "Advanced",
        description:
          "Opt for a platform that implements forward secrecy. This is where your app generates a new encryption key for every message.",
      },
      {
        id: "msg-19",
        title: "Consider a Decentralized Platform",
        level: "Advanced",
        description:
          "If all data flows through a central provider, you have to trust them with your data and meta-data. You cannot verify that the system running is authentic without back doors.",
      },
    ],
  },
  {
    id: "social-media",
    label: "Social Media",
    icon: "groups",
    color: "#f43f5e",
    colorClass: "rose",
    description:
      "Social networking sites give people around the world the opportunity to connect and share, but they have serious privacy concerns. These sites collect data about individuals and sell it to third-party advertisers. Secure your account and lock down your privacy settings.",
    items: [
      {
        id: "sm-1",
        title: "Secure your Account",
        level: "Essential",
        description:
          "Social media profiles get stolen or taken over all too often. To protect your account: use a unique and strong password, and enable 2-factor authentication.",
      },
      {
        id: "sm-2",
        title: "Check Privacy Settings",
        level: "Essential",
        description:
          "Most social networks allow you to control your privacy settings. Ensure that you are comfortable with what data you are currently exposing and to whom.",
      },
      {
        id: "sm-3",
        title: "Think of All Interactions as Public",
        level: "Essential",
        description:
          "There are still numerous methods of viewing a users 'private' content across many social networks. Therefore, before uploading, posting or commenting on anything, think \"Would I mind if this was totally public?\"",
      },
      {
        id: "sm-4",
        title: "Think of All Interactions as Permanent",
        level: "Essential",
        description:
          "Pretty much every post, comment, photo etc is being continuously backed up by a myriad of third-party services, who archive this data and make it indexable and publicly available almost forever.",
      },
      {
        id: "sm-5",
        title: "Don't Reveal too Much",
        level: "Essential",
        description:
          "Profile information creates a goldmine of info for hackers, the kind of data that helps them personalize phishing scams. Avoid sharing too much detail (DoB, Hometown, School etc).",
      },
      {
        id: "sm-6",
        title: "Be Careful what you Upload",
        level: "Essential",
        description:
          "Status updates, comments, check-ins and media can unintentionally reveal a lot more than you intended them to. This is especially relevant to photos and videos, which may show things in the background.",
      },
      {
        id: "sm-7",
        title: "Don't Share Email or Phone Number",
        level: "Essential",
        description:
          "Posting your real email address or mobile number, gives hackers, trolls and spammers more munition to use against you, and can also allow separate aliases, profiles or data points to be connected.",
      },
      {
        id: "sm-8",
        title: "Don't Grant Unnecessary Permissions",
        level: "Essential",
        description:
          "By default many of the popular social networking apps will ask for permission to access your contacts, call log, location, messaging history etc. If they don’t need this access, don’t grant it.",
      },
      {
        id: "sm-9",
        title: "Be Careful of 3rd-Party Integrations",
        level: "Essential",
        description:
          "Avoid signing up for accounts using a Social Network login, revoke access to social apps you no longer use.",
      },
      {
        id: "sm-10",
        title: "Avoid Publishing Geo Data while still Onsite",
        level: "Essential",
        description:
          "If you plan to share any content that reveals a location, then wait until you have left that place. This is particularly important when you are taking a trip, at a restaurant, campus, hotel/resort, public building or airport.",
      },
      {
        id: "sm-11",
        title: "Remove metadata before uploading media",
        level: "Optional",
        description:
          "Most smartphones and some cameras automatically attach a comprehensive set of additional data (called EXIF data) to each photograph. Remove this data before uploading.",
      },
      {
        id: "sm-12",
        title: "Implement Image Cloaking",
        level: "Advanced",
        description:
          "Tools like Fawkes can be used to very subtly, slightly change the structure of faces within photos in a way that is imperceptible by humans, but will prevent facial recognition systems from being able to recognize a given face.",
      },
      {
        id: "sm-13",
        title: "Consider Spoofing GPS in home vicinity",
        level: "Advanced",
        description:
          "Even if you yourself never use social media, there is always going to be others who are not as careful, and could reveal your location.",
      },
      {
        id: "sm-14",
        title: "Consider False Information",
        level: "Advanced",
        description:
          "If you just want to read, and do not intend on posting too much- consider using an alias name, and false contact details.",
      },
      {
        id: "sm-15",
        title: "Don’t have any social media accounts",
        level: "Advanced",
        description:
          "Social media is fundamentally un-private, so for maximum online security and privacy, avoid using any mainstream social networks.",
      },
    ],
  },
  {
    id: "networks",
    label: "Networks",
    icon: "router",
    color: "#f59e0b",
    colorClass: "amber",
    description:
      "This section covers how you connect your devices to the internet securely, including configuring your router and setting up a VPN. Keeping network connections secure is foundational to overall digital security.",
    items: [
      {
        id: "net-1",
        title: "Use a VPN",
        level: "Essential",
        description:
          "Use a reputable, paid-for VPN. This can help protect sites you visit from logging your real IP, reduce the amount of data your ISP can collect, and increase protection on public WiFi.",
      },
      {
        id: "net-2",
        title: "Change your Router Password",
        level: "Essential",
        description:
          "After getting a new router, change the password. Default router passwords are publicly available, meaning anyone within proximity would be able to connect.",
      },
      {
        id: "net-3",
        title: "Use WPA2, and a strong password",
        level: "Essential",
        description:
          "There are different authentication protocols for connecting to WiFi. Currently, the most secure options are WPA2 and WPA3 (on newer routers).",
      },
      {
        id: "net-4",
        title: "Keep router firmware up-to-date",
        level: "Essential",
        description:
          "Manufacturers release firmware updates that fix security vulnerabilities, implement new standards, and sometimes add features or improve the performance of your router.",
      },
      {
        id: "net-5",
        title: "Implement a Network-Wide VPN",
        level: "Optional",
        description:
          "If you configure your VPN on your router, firewall, or home server, then traffic from all devices will be encrypted and routed through it, without needing individual VPN apps.",
      },
      {
        id: "net-6",
        title: "Protect against DNS leaks",
        level: "Optional",
        description:
          "When using a VPN, it is extremely important to exclusively use the DNS server of your VPN provider or secure service.",
      },
      {
        id: "net-7",
        title: "Use a secure VPN Protocol",
        level: "Optional",
        description:
          "OpenVPN and WireGuard are open source, lightweight, and secure tunneling protocols. Avoid using PPTP or SSTP.",
      },
      {
        id: "net-8",
        title: "Secure DNS",
        level: "Optional",
        description:
          "Use DNS-over-HTTPS which performs DNS resolution via the HTTPS protocol, encrypting data between you and your DNS resolver.",
      },
      {
        id: "net-9",
        title: "Avoid the free router from your ISP",
        level: "Optional",
        description:
          "Typically they’re manufactured cheaply in bulk in China, with insecure propriety firmware that doesn't receive regular security updates.",
      },
      {
        id: "net-10",
        title: "Whitelist MAC Addresses",
        level: "Optional",
        description:
          "You can whitelist MAC addresses in your router settings, disallowing any unknown devices to immediately connect to your network, even if they know your credentials.",
      },
      {
        id: "net-11",
        title: "Change the Router’s Local IP Address",
        level: "Optional",
        description:
          "It is possible for a malicious script in your web browser to exploit a cross-site scripting vulnerability, accessing known-vulnerable routers at their local IP address and tampering with them.",
      },
      {
        id: "net-12",
        title: "Don't Reveal Personal Info in SSID",
        level: "Optional",
        description:
          "You should update your network name, choosing an SSID that does not identify you, include your flat number/address, and does not specify the device brand/model.",
      },
      {
        id: "net-13",
        title: "Opt-Out Router Listings",
        level: "Optional",
        description:
          "WiFi SSIDs are scanned, logged, and then published on various websites, which is a serious privacy concern for some.",
      },
      {
        id: "net-14",
        title: "Hide your SSID",
        level: "Optional",
        description:
          "Your router's Service Set Identifier is simply the network name. If it is not visible, it may receive less abuse.",
      },
      {
        id: "net-15",
        title: "Disable WPS",
        level: "Optional",
        description:
          "Wi-Fi Protected Setup provides an easier method to connect, without entering a long WiFi password, but WPS introduces a series of major security issues.",
      },
      {
        id: "net-16",
        title: "Disable UPnP",
        level: "Optional",
        description:
          "Universal Plug and Play allows applications to automatically forward a port on your router, but it has a long history of serious security issues.",
      },
      {
        id: "net-17",
        title: "Use a Guest Network for Guests",
        level: "Optional",
        description:
          "Do not grant access to your primary WiFi network to visitors, as it enables them to interact with other devices on the network.",
      },
      {
        id: "net-18",
        title: "Change your Router's Default IP",
        level: "Optional",
        description:
          "Modifying your router admin panel's default IP address will make it more difficult for malicious scripts targeting local IP addresses.",
      },
      {
        id: "net-19",
        title: "Kill unused processes and services on your router",
        level: "Optional",
        description:
          "Services like Telnet and SSH that provide command-line access to devices should never be exposed to the internet and should also be disabled on the local network unless they're actually needed.",
      },
      {
        id: "net-20",
        title: "Don't have Open Ports",
        level: "Optional",
        description:
          "Close any open ports on your router that are not needed. Open ports provide an easy entrance for hackers.",
      },
      {
        id: "net-21",
        title: "Disable Unused Remote Access Protocols",
        level: "Optional",
        description:
          "When protocols such as PING, Telnet, SSH, UPnP, and HNAP etc are enabled, they allow your router to be probed from anywhere in the world.",
      },
      {
        id: "net-22",
        title: "Disable Cloud-Based Management",
        level: "Optional",
        description:
          "You should treat your router's admin panel with the utmost care, as considerable damage can be caused if an attacker is able to gain access.",
      },
      {
        id: "net-23",
        title: "Manage Range Correctly",
        level: "Optional",
        description:
          "It's common to want to pump your router's range to the max, but if you reside in a smaller flat, your attack surface is increased when your WiFi network can be picked up across the street.",
      },
      {
        id: "net-24",
        title: "Route all traffic through Tor",
        level: "Advanced",
        description:
          "VPNs have their weaknesses. For increased security, route all your internet traffic through the Tor network.",
      },
      {
        id: "net-25",
        title: "Disable WiFi on all Devices",
        level: "Advanced",
        description:
          "Connecting to even a secure WiFi network increases your attack surface. Disabling your home WiFi and connect each device via Ethernet.",
      },
    ],
  },
  {
    id: "mobile-devices",
    label: "Mobile Devices",
    icon: "smartphone",
    color: "#3b82f6",
    colorClass: "blue",
    description:
      "Smart phones have revolutionized life but also carry serious privacy risks. Geo-tracking traces every move, microphones can eavesdrop, and cameras can watch you. Using a smartphone generates a lot of data about you — take steps to minimize the risks.",
    items: [
      {
        id: "mob-1",
        title: "Encrypt your Device",
        level: "Essential",
        description:
          "In order to keep your data safe from physical access, use file encryption. This will mean if your device is lost or stolen, no one will have access to your data.",
      },
      {
        id: "mob-2",
        title: "Turn off connectivity features that aren’t being used",
        level: "Essential",
        description:
          "When you're not using WiFi, Bluetooth, NFC etc, turn those features off. There are several common threats that utilise these features.",
      },
      {
        id: "mob-3",
        title: "Keep app count to a minimum",
        level: "Essential",
        description:
          "Uninstall apps that you don’t need or use regularly. As apps often run in the background, slowing your device down, but also collecting data.",
      },
      {
        id: "mob-4",
        title: "App Permissions",
        level: "Essential",
        description:
          "Don’t grant apps permissions that they don’t need. For Android, Bouncer is an app that allows you to grant temporary/ 1-off permissions.",
      },
      {
        id: "mob-5",
        title: "Only install Apps from official source",
        level: "Essential",
        description:
          "Applications on Apple App Store and Google Play Store are scanned and cryptographically signed, making them less likely to be malicious.",
      },
      {
        id: "mob-6",
        title: "Be Careful of Phone Charging Threats",
        level: "Optional",
        description:
          "Juice Jacking is when hackers use public charging stations to install malware on your smartphone or tablet through a compromised USB port.",
      },
      {
        id: "mob-7",
        title: "Set up a mobile carrier PIN",
        level: "Essential",
        description:
          "SIM hijacking is when a hacker is able to get your mobile number transferred to their sim. The easiest way to protect against this is to set up a PIN through your mobile provider.",
      },
      {
        id: "mob-8",
        title: "Opt-out of Caller ID Listings",
        level: "Optional",
        description:
          "To keep your details private, you can unlist your number from caller ID apps like TrueCaller, CallApp, SyncMe, and Hiya.",
      },
      {
        id: "mob-9",
        title: "Use Offline Maps",
        level: "Optional",
        description:
          "Consider using an offline maps app, such as OsmAnd or Organic Maps, to reduce data leaks from map apps.",
      },
      {
        id: "mob-10",
        title: "Opt-out of personalized ads",
        level: "Optional",
        description:
          "You can slightly reduce the amount of data collected by opting-out of seeing personalized ads.",
      },
      {
        id: "mob-11",
        title: "Erase after too many login attempts",
        level: "Optional",
        description:
          "To protect against an attacker brute forcing your pin, set your device to erase after too many failed login attempts.",
      },
      {
        id: "mob-12",
        title: "Monitor Trackers",
        level: "Optional",
        description:
          "εxodus is a great service which lets you search for any app and see which trackers are embedded in it.",
      },
      {
        id: "mob-13",
        title: "Use a Mobile Firewall",
        level: "Optional",
        description:
          "To prevent applications from leaking privacy-sensitive data, you can install a firewall app.",
      },
      {
        id: "mob-14",
        title: "Reduce Background Activity",
        level: "Optional",
        description:
          "For Android, SuperFreeze makes it possible to entirely freeze all background activities on a per-app basis.",
      },
      {
        id: "mob-15",
        title: "Sandbox Mobile Apps",
        level: "Optional",
        description:
          "Prevent permission-hungry apps from accessing your private data with Island, a sandbox environment.",
      },
      {
        id: "mob-16",
        title: "Tor Traffic",
        level: "Advanced",
        description:
          "Orbot provides a system-wide Tor connection, which will help protect you from surveillance and public WiFi threats.",
      },
      {
        id: "mob-17",
        title: "Avoid Custom Virtual Keyboards",
        level: "Optional",
        description:
          "It is recommended to stick with your device's stock keyboard. If you choose to use a third-party keyboard app, ensure it is reputable.",
      },
      {
        id: "mob-18",
        title: "Restart Device Regularly",
        level: "Optional",
        description:
          "Restarting your phone at least once a week will clear the app state cached in memory and may run more smoothly after a restart.",
      },
      {
        id: "mob-19",
        title: "Avoid SMS",
        level: "Optional",
        description:
          "SMS should not be used to receive 2FA codes or for communication, instead use an encrypted messaging app, such as Signal.",
      },
      {
        id: "mob-20",
        title: "Keep your Number Private",
        level: "Optional",
        description:
          "MySudo allows you to create and use virtual phone numbers for different people or groups. This is great for compartmentalisation.",
      },
      {
        id: "mob-21",
        title: "Watch out for Stalkerware",
        level: "Optional",
        description:
          "Stalkerware is malware that is installed directly onto your device by someone you know. The best way to get rid of it is through a factory reset.",
      },
      {
        id: "mob-22",
        title: "Favor the Browser, over Dedicated App",
        level: "Optional",
        description:
          "Where possible, consider using a secure browser to access sites, rather than installing dedicated applications.",
      },
      {
        id: "mob-23",
        title: "Consider running a custom ROM (Android)",
        level: "Advanced",
        description:
          "If you're concerned about your device manufacturer collecting too much personal information, consider a privacy-focused custom ROM.",
      },
    ],
  },
  {
    id: "personal-computers",
    label: "Personal Computers",
    icon: "laptop",
    color: "#64748b",
    colorClass: "slate",
    description:
      "Although Windows and OS X are easy to use and convenient, they both are far from secure. Your OS provides the interface between hardware and your applications, so if compromised it can have detrimental effects. Take steps to lock down your desktop environment.",
    items: [
      {
        id: "pc-1",
        title: "Keep your System up-to-date",
        level: "Essential",
        description:
          "System updates contain fixes/patches for security issues, improve performance, and sometimes add new features. Install new updates when prompted.",
      },
      {
        id: "pc-2",
        title: "Encrypt your Device",
        level: "Essential",
        description:
          "Use BitLocker for Windows, FileVault on MacOS, or LUKS on Linux, to enable full disk encryption. This prevents unauthorized access if your computer is lost or stolen.",
      },
      {
        id: "pc-3",
        title: "Backup Important Data",
        level: "Essential",
        description:
          "Maintaining encrypted backups prevents loss due to ransomware, theft, or damage. Consider using Cryptomator for cloud files or VeraCrypt for USB drives.",
      },
      {
        id: "pc-4",
        title: "Be Careful Plugging USB Devices into your Computer",
        level: "Essential",
        description:
          "USB devices can pose serious threats. Consider making a USB sanitizer with CIRCLean to safely check USB devices.",
      },
      {
        id: "pc-5",
        title: "Activate Screen-Lock when Idle",
        level: "Essential",
        description:
          "Lock your computer when away and set it to require a password on resume from screensaver or sleep to prevent unauthorized access.",
      },
      {
        id: "pc-6",
        title: "Disable Cortana or Siri",
        level: "Essential",
        description:
          "Voice-controlled assistants can have privacy implications due to data sent back for processing. Disable or limit their listening capabilities.",
      },
      {
        id: "pc-7",
        title: "Review your Installed Apps",
        level: "Essential",
        description:
          "Keep installed applications to a minimum to reduce exposure to vulnerabilities and regularly clear application caches.",
      },
      {
        id: "pc-8",
        title: "Manage Permissions",
        level: "Essential",
        description:
          "Control which apps have access to your location, camera, microphone, contacts, and other sensitive information.",
      },
      {
        id: "pc-9",
        title: "Disallow Usage Data from being sent to the Cloud",
        level: "Essential",
        description:
          "Limit the amount of usage information or feedback sent to the cloud to protect your privacy.",
      },
      {
        id: "pc-10",
        title: "Avoid Quick Unlock",
        level: "Essential",
        description:
          "Use a strong password instead of biometrics or short PINs for unlocking your computer to enhance security.",
      },
      {
        id: "pc-11",
        title: "Power Off Computer, instead of Standby",
        level: "Essential",
        description:
          "Shut down your device when not in use, especially if your disk is encrypted, to keep data secure.",
      },
      {
        id: "pc-12",
        title: "Don't link your PC with your Microsoft or Apple Account",
        level: "Optional",
        description:
          "Use a local account only to prevent data syncing and exposure. Avoid using sync services that compromise privacy.",
      },
      {
        id: "pc-13",
        title: "Check which Sharing Services are Enabled",
        level: "Optional",
        description:
          "Disable network sharing features you are not using to close gateways to common threats.",
      },
      {
        id: "pc-14",
        title: "Don't use Root/Admin Account for Non-Admin Tasks",
        level: "Optional",
        description:
          "Use an unprivileged user account for daily tasks and only elevate permissions for administrative changes to mitigate vulnerabilities.",
      },
      {
        id: "pc-15",
        title: "Block Webcam + Microphone",
        level: "Optional",
        description:
          "Cover your webcam when not in use and consider blocking unauthorized audio recording to protect privacy.",
      },
      {
        id: "pc-16",
        title: "Use a Privacy Filter",
        level: "Optional",
        description:
          "Use a screen privacy filter in public spaces to prevent shoulder surfing and protect sensitive information.",
      },
      {
        id: "pc-17",
        title: "Physically Secure Device",
        level: "Optional",
        description:
          "Use a Kensington Lock to secure your laptop in public spaces and consider port locks to prevent unauthorized physical access.",
      },
      {
        id: "pc-18",
        title: "Don't Charge Devices from your PC",
        level: "Optional",
        description:
          "Use a power bank or AC wall charger instead of your PC to avoid security risks associated with USB connections.",
      },
      {
        id: "pc-19",
        title: "Randomize your hardware address on Wi-Fi",
        level: "Optional",
        description:
          "Modify or randomize your MAC address to protect against tracking across different WiFi networks.",
      },
      {
        id: "pc-20",
        title: "Use a Firewall",
        level: "Optional",
        description:
          "Install a firewall app to monitor and block unwanted internet access by certain applications, protecting against remote access attacks and privacy breaches.",
      },
      {
        id: "pc-21",
        title: "Protect Against Software Keyloggers",
        level: "Optional",
        description:
          "Use key stroke encryption tools to protect against software keyloggers recording your keystrokes.",
      },
      {
        id: "pc-22",
        title: "Check Keyboard Connection",
        level: "Optional",
        description:
          "Be vigilant for hardware keyloggers when using public or unfamiliar computers by checking keyboard connections.",
      },
      {
        id: "pc-23",
        title: "Prevent Keystroke Injection Attacks",
        level: "Optional",
        description:
          "Lock your PC when away and consider using USBGuard or similar tools to protect against keystroke injection attacks.",
      },
      {
        id: "pc-24",
        title: "Don't use commercial \"Free\" Anti-Virus",
        level: "Optional",
        description:
          "Rely on built-in security tools and avoid free anti-virus applications due to their potential for privacy invasion and data collection.",
      },
      {
        id: "pc-25",
        title: "Periodically check for Rootkits",
        level: "Advanced",
        description:
          "Regularly check for rootkits to detect and mitigate full system control threats using tools like chkrootkit.",
      },
      {
        id: "pc-26",
        title: "BIOS Boot Password",
        level: "Advanced",
        description:
          "Enable a BIOS or UEFI password to add an additional security layer during boot-up, though be aware of its limitations.",
      },
      {
        id: "pc-27",
        title: "Use a Security-Focused Operating System",
        level: "Advanced",
        description:
          "Consider switching to Linux or a security-focused distro like QubeOS or Tails for enhanced privacy and security.",
      },
      {
        id: "pc-28",
        title: "Make Use of VMs",
        level: "Advanced",
        description:
          "Use virtual machines for risky activities or testing suspicious software to isolate potential threats from your primary system.",
      },
      {
        id: "pc-29",
        title: "Compartmentalize",
        level: "Advanced",
        description:
          "Isolate different programs and data sources from one another as much as possible to limit the extent of potential breaches.",
      },
      {
        id: "pc-30",
        title: "Disable Undesired Features (Windows)",
        level: "Advanced",
        description:
          "Disable unnecessary Windows \"features\" and services that run in the background to reduce data collection and resource use.",
      },
      {
        id: "pc-31",
        title: "Secure Boot",
        level: "Advanced",
        description:
          "Ensure that Secure Boot is enabled to prevent malware from replacing your boot loader and other critical software.",
      },
      {
        id: "pc-32",
        title: "Secure SSH Access",
        level: "Advanced",
        description:
          "Take steps to protect SSH access from attacks by changing the default port, using SSH keys, and configuring firewalls.",
      },
      {
        id: "pc-33",
        title: "Close Un-used Open Ports",
        level: "Advanced",
        description:
          "Turn off services listening on external ports that are not needed to protect against remote exploits and improve security.",
      },
      {
        id: "pc-34",
        title: "Implement Mandatory Access Control",
        level: "Advanced",
        description:
          "Restrict privileged access to limit the damage that can be done if a system is compromised.",
      },
      {
        id: "pc-35",
        title: "Use Canary Tokens",
        level: "Advanced",
        description:
          "Deploy canary tokens to detect unauthorized access to your files or emails faster and gather information about the intruder.",
      },
    ],
  },
  {
    id: "smart-home",
    label: "Smart Home",
    icon: "home",
    color: "#f97316",
    colorClass: "orange",
    description:
      "Home assistants and internet-connected devices collect large amounts of personal data. There is a trade-off between convenience and privacy. The following checklist helps mitigate risks associated with internet-connected home devices.",
    items: [
      {
        id: "sh-1",
        title: "Rename devices to not specify brand/model",
        level: "Essential",
        description:
          "Change default device names to something generic to prevent targeted attacks by obscuring brand or model information.",
      },
      {
        id: "sh-2",
        title: "Disable microphone and camera when not in use",
        level: "Essential",
        description:
          "Use hardware switches to turn off microphones and cameras on smart devices to protect against accidental recordings or targeted access.",
      },
      {
        id: "sh-3",
        title: "Understand what data is collected, stored and transmitted",
        level: "Essential",
        description:
          "Research and ensure comfort with the data handling practices of smart home devices before purchase, avoiding devices that share data with third parties.",
      },
      {
        id: "sh-4",
        title: "Set privacy settings, and opt out of sharing data with third parties",
        level: "Essential",
        description:
          "Adjust app settings for strictest privacy controls and opt-out of data sharing with third parties wherever possible.",
      },
      {
        id: "sh-5",
        title: "Don't link your smart home devices to your real identity",
        level: "Essential",
        description:
          "Use anonymous usernames and passwords, avoiding sign-up/log-in via social media or other third-party services to maintain privacy.",
      },
      {
        id: "sh-6",
        title: "Keep firmware up-to-date",
        level: "Essential",
        description:
          "Regularly update smart device firmware to apply security patches and enhancements.",
      },
      {
        id: "sh-7",
        title: "Protect your Network",
        level: "Essential",
        description:
          "Secure your home WiFi and network to prevent unauthorized access to smart devices.",
      },
      {
        id: "sh-8",
        title: "Be wary of wearables",
        level: "Optional",
        description:
          "Consider the extensive data collection capabilities of wearable devices and their implications for privacy.",
      },
      {
        id: "sh-9",
        title: "Don't connect your home's critical infrastructure to the Internet",
        level: "Optional",
        description:
          "Evaluate the risks of internet-connected thermostats, alarms, and detectors due to potential remote access by hackers.",
      },
      {
        id: "sh-10",
        title: "Mitigate Alexa/ Google Home Risks",
        level: "Optional",
        description:
          "Consider privacy-focused alternatives like Mycroft or use Project Alias to prevent idle listening by voice-activated assistants.",
      },
      {
        id: "sh-11",
        title: "Monitor your home network closely",
        level: "Optional",
        description:
          "Use tools like FingBox or router features to monitor for unusual network activity.",
      },
      {
        id: "sh-12",
        title: "Deny Internet access where possible",
        level: "Advanced",
        description:
          "Use firewalls to block internet access for devices that don't need it, limiting operation to local network use.",
      },
      {
        id: "sh-13",
        title: "Assess risks",
        level: "Advanced",
        description:
          "Consider the privacy implications for all household members and adjust device settings for security and privacy, such as disabling devices at certain times.",
      },
    ],
  },
  {
    id: "personal-finance",
    label: "Personal Finance",
    icon: "account_balance",
    color: "#22c55e",
    colorClass: "green",
    description:
      "Credit card fraud is the most common form of identity theft. It is more important than ever to take basic steps to protect yourself from financial fraud and identity theft. Note that credit cards are good for security but terrible for data privacy.",
    items: [
      {
        id: "fin-1",
        title: "Sign up for Fraud Alerts and Credit Monitoring",
        level: "Essential",
        description:
          "Enable fraud alerts and credit monitoring through Experian, TransUnion, or Equifax to be alerted of suspicious activity.",
      },
      {
        id: "fin-2",
        title: "Apply a Credit Freeze",
        level: "Essential",
        description:
          "Prevent unauthorized credit inquiries by freezing your credit through Experian, TransUnion, and Equifax.",
      },
      {
        id: "fin-3",
        title: "Use Virtual Cards",
        level: "Optional",
        description:
          "Utilize virtual card numbers for online transactions to protect your real banking details. Services like Privacy.com and MySudo offer such features.",
      },
      {
        id: "fin-4",
        title: "Use Cash for Local Transactions",
        level: "Optional",
        description:
          "Pay with Cash for local and everyday purchases to avoid financial profiling by institutions.",
      },
      {
        id: "fin-5",
        title: "Use Cryptocurrency for Online Transactions",
        level: "Optional",
        description:
          "Opt for privacy-focused cryptocurrencies like Monero for online transactions to maintain anonymity. Use cryptocurrencies wisely to ensure privacy.",
      },
      {
        id: "fin-6",
        title: "Store Crypto Securely",
        level: "Advanced",
        description:
          "Securely store cryptocurrencies using offline wallet generation, hardware wallets like Trezor or ColdCard, or consider long-term storage solutions like CryptoSteel.",
      },
      {
        id: "fin-7",
        title: "Buy Crypto Anonymously",
        level: "Advanced",
        description:
          "Purchase cryptocurrencies without linking to your identity through services like LocalBitcoins, Bisq, or Bitcoin ATMs.",
      },
      {
        id: "fin-8",
        title: "Tumble/ Mix Coins",
        level: "Advanced",
        description:
          "Use a bitcoin mixer or CoinJoin before converting Bitcoin to currency to obscure transaction trails.",
      },
      {
        id: "fin-9",
        title: "Use an Alias Details for Online Shopping",
        level: "Advanced",
        description:
          "For online purchases, consider using alias details, forwarding email addresses, VOIP numbers, and secure delivery methods to protect your identity.",
      },
      {
        id: "fin-10",
        title: "Use alternate delivery address",
        level: "Advanced",
        description:
          "Opt for deliveries to non-personal addresses such as PO Boxes, forwarding addresses, or local pickup locations to avoid linking purchases directly to you.",
      },
    ],
  },
  {
    id: "human-aspect",
    label: "Human Aspect",
    icon: "psychology",
    color: "#ec4899",
    colorClass: "pink",
    description:
      "Many data breaches, hacks, and attacks are caused by human error. The following list contains steps you should take to reduce the risk of this happening to you. Many are common sense, but it's worth taking note of them.",
    items: [
      {
        id: "hum-1",
        title: "Verify Recipients",
        level: "Essential",
        description:
          "Emails can be easily spoofed. Verify the sender's authenticity, especially for sensitive actions, and prefer entering URLs manually rather than clicking links in emails.",
      },
      {
        id: "hum-2",
        title: "Don't Trust Your Popup Notifications",
        level: "Essential",
        description:
          "Fake pop-ups can be deployed by malicious actors. Always check the URL before entering any information on a popup.",
      },
      {
        id: "hum-3",
        title: "Never Leave Device Unattended",
        level: "Essential",
        description:
          "Unattended devices can be compromised even with strong passwords. Use encryption and remote erase features like Find My Phone for lost devices.",
      },
      {
        id: "hum-4",
        title: "Prevent Camfecting",
        level: "Essential",
        description:
          "Protect against camfecting by using webcam covers and microphone blockers. Mute home assistants when not in use or discussing sensitive matters.",
      },
      {
        id: "hum-5",
        title: "Stay protected from shoulder surfers",
        level: "Essential",
        description:
          "Use privacy screens on laptops and mobiles to prevent others from reading your screen in public spaces.",
      },
      {
        id: "hum-6",
        title: "Educate yourself about phishing attacks",
        level: "Essential",
        description:
          "Be cautious of phishing attempts. Verify URLs, context of received messages, and employ good security practices like using 2FA and not reusing passwords.",
      },
      {
        id: "hum-7",
        title: "Watch out for Stalkerware",
        level: "Essential",
        description:
          "Be aware of stalkerware installed by acquaintances for spying. Look out for signs like unusual battery usage and perform factory resets if suspected.",
      },
      {
        id: "hum-8",
        title: "Install Reputable Software from Trusted Sources",
        level: "Essential",
        description:
          "Only download software from legitimate sources and check files with tools like Virus Total before installation.",
      },
      {
        id: "hum-9",
        title: "Store personal data securely",
        level: "Essential",
        description:
          "Ensure all personal data on devices or in the cloud is encrypted to protect against unauthorized access.",
      },
      {
        id: "hum-10",
        title: "Obscure Personal Details from Documents",
        level: "Essential",
        description:
          "When sharing documents, obscure personal details with opaque rectangles to prevent information leakage.",
      },
      {
        id: "hum-11",
        title: "Do not assume a site is secure, just because it is HTTPS",
        level: "Essential",
        description:
          "HTTPS does not guarantee a website's legitimacy. Verify URLs and exercise caution with personal data.",
      },
      {
        id: "hum-12",
        title: "Use Virtual Cards when paying online",
        level: "Optional",
        description:
          "Use virtual cards for online payments to protect your banking details and limit transaction risks.",
      },
      {
        id: "hum-13",
        title: "Review application permissions",
        level: "Optional",
        description:
          "Regularly review and manage app permissions to ensure no unnecessary access to sensitive device features.",
      },
      {
        id: "hum-14",
        title: "Opt-out of public lists",
        level: "Optional",
        description:
          "Remove yourself from public databases and marketing lists to reduce unwanted contacts and potential risks.",
      },
      {
        id: "hum-15",
        title: "Never Provide Additional PII When Opting-Out",
        level: "Optional",
        description:
          "Do not provide additional personal information when opting out of data services to avoid further data collection.",
      },
      {
        id: "hum-16",
        title: "Opt-out of data sharing",
        level: "Optional",
        description:
          "Many apps and services default to data sharing settings. Opt out to protect your data from being shared with third parties.",
      },
      {
        id: "hum-17",
        title: "Review and update social media privacy",
        level: "Optional",
        description:
          "Regularly check and update your social media settings due to frequent terms updates that may affect your privacy settings.",
      },
      {
        id: "hum-18",
        title: "Compartmentalize",
        level: "Advanced",
        description:
          "Keep different areas of digital activity separate to limit data exposure in case of a breach.",
      },
      {
        id: "hum-19",
        title: "WhoIs Privacy Guard",
        level: "Advanced",
        description:
          "Use WhoIs Privacy Guard for domain registrations to protect your information from public searches.",
      },
      {
        id: "hum-20",
        title: "Use a forwarding address",
        level: "Advanced",
        description:
          "Use a PO Box or forwarding address for mail to prevent companies from knowing your real address, adding a layer of privacy protection.",
      },
      {
        id: "hum-21",
        title: "Use anonymous payment methods",
        level: "Advanced",
        description:
          "Opt for anonymous payment methods like cryptocurrencies to avoid entering identifiable information online.",
      },
    ],
  },
  {
    id: "physical-security",
    label: "Physical Security",
    icon: "security",
    color: "#ef4444",
    colorClass: "red",
    description:
      "Strong authentication, encrypted devices, and patched software may be of little use if someone is able to physically compromise you, your devices, and your data. This section outlines basic methods for physical security against real-world threats.",
    items: [
      {
        id: "phys-1",
        title: "Destroy Sensitive Documents",
        level: "Essential",
        description:
          "Shred or redact sensitive documents before disposal to protect against identity theft and maintain confidentiality.",
      },
      {
        id: "phys-2",
        title: "Opt-Out of Public Records",
        level: "Essential",
        description:
          "Contact people search websites to opt-out from listings that show persona information, using guides like Michael Bazzell's Personal Data Removal Workbook.",
      },
      {
        id: "phys-3",
        title: "Watermark Documents",
        level: "Essential",
        description:
          "Add a watermark with the recipient's name and date to digital copies of personal documents to trace the source of a breach.",
      },
      {
        id: "phys-4",
        title: "Don't Reveal Info on Inbound Calls",
        level: "Essential",
        description:
          "Only share personal data on calls you initiate and verify the recipient's phone number.",
      },
      {
        id: "phys-5",
        title: "Stay Alert",
        level: "Essential",
        description:
          "Be aware of your surroundings and assess potential risks in new environments.",
      },
      {
        id: "phys-6",
        title: "Secure Perimeter",
        level: "Essential",
        description:
          "Ensure physical security of locations storing personal info devices, minimizing external access and using intrusion detection systems.",
      },
      {
        id: "phys-7",
        title: "Physically Secure Devices",
        level: "Essential",
        description:
          "Use physical security measures like Kensington locks, webcam covers, and privacy screens for devices.",
      },
      {
        id: "phys-8",
        title: "Keep Devices Out of Direct Sight",
        level: "Essential",
        description:
          "Prevent devices from being visible from outside to mitigate risks from lasers and theft.",
      },
      {
        id: "phys-9",
        title: "Protect your PIN",
        level: "Essential",
        description:
          "Shield your PIN entry from onlookers and cameras, and clean touchscreens after use.",
      },
      {
        id: "phys-10",
        title: "Check for Skimmers",
        level: "Essential",
        description:
          "Inspect ATMs and public devices for skimming devices and tampering signs before use.",
      },
      {
        id: "phys-11",
        title: "Protect your Home Address",
        level: "Optional",
        description:
          "Use alternative locations, forwarding addresses, and anonymous payment methods to protect your home address.",
      },
      {
        id: "phys-12",
        title: "Use a PIN, Not Biometrics",
        level: "Advanced",
        description:
          "Prefer PINs over biometrics for device security in situations where legal coercion to unlock devices may occur.",
      },
      {
        id: "phys-13",
        title: "Reduce exposure to CCTV",
        level: "Advanced",
        description:
          "Wear disguises and choose routes with fewer cameras to avoid surveillance.",
      },
      {
        id: "phys-14",
        title: "Anti-Facial Recognition Clothing",
        level: "Advanced",
        description:
          "Wear clothing with patterns that trick facial-recognition technology.",
      },
      {
        id: "phys-15",
        title: "Reduce Night Vision Exposure",
        level: "Advanced",
        description:
          "Use IR light sources or reflective glasses to obstruct night vision cameras.",
      },
      {
        id: "phys-16",
        title: "Protect your DNA",
        level: "Advanced",
        description:
          "Avoid sharing DNA with heritage websites and be cautious about leaving DNA traces.",
      },
    ],
  },
];

export const SECTION_MAP = Object.fromEntries(
  CHECKLIST_SECTIONS.map((s) => [s.id, s])
);

export function getInitialChecks() {
  try {
    const saved = localStorage.getItem("dd_checklist_v2");
    return saved ? JSON.parse(saved) : {};
  } catch {
    return {};
  }
}

export function saveChecks(checks) {
  try {
    localStorage.setItem("dd_checklist_v2", JSON.stringify(checks));
  } catch {
    // ignore
  }
}

export function computeSectionProgress(sectionId, checks) {
  const section = SECTION_MAP[sectionId];
  if (!section) return 0;
  const total = section.items.length;
  if (total === 0) return 0;
  const done = section.items.filter((item) => checks[item.id] === true).length;
  return Math.round((done / total) * 100);
}

export function computeOverallProgress(checks) {
  const allItems = CHECKLIST_SECTIONS.flatMap((s) => s.items);
  const total = allItems.length;
  if (total === 0) return 0;
  const done = allItems.filter((item) => checks[item.id] === true).length;
  return Math.round((done / total) * 100);
}
