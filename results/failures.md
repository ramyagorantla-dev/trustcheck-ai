# Failure analysis

Every misclassified example, per system. FN = scam marked safe (the dangerous error); FP = genuine message flagged.


## classic_tfidf_lr: 11 errors

### tc004 · sms · otp_takeover · FN (missed scam) · score 46.0
```
Hi it's Priya, I accidentally sent my verification code to your number, can you send me the 6 digit code please? urgent
```
Why it failed (fill in): 

### tc010 · sms · crypto · FN (missed scam) · score 49.0
```
Hey, long time no see! My uncle showed me a crypto platform with guaranteed 30% weekly returns. I can help you set up a wallet, just send USDT to start.
```
Why it failed (fill in): 

### tc012 · sms · otp_genuine · FP (false alarm) · score 52.0
```
Your Google verification code is 482913. Don't share this code with anyone.
```
Why it failed (fill in): 

### tc013 · sms · delivery · FP (false alarm) · score 51.0
```
Your Amazon package was delivered. Track at https://www.amazon.com/your-orders
```
Why it failed (fill in): 

### tc014 · sms · appointment · FP (false alarm) · score 50.0
```
Reminder: Your dentist appointment with Dr. Lee is on Thursday at 3:30 PM. Reply C to confirm or call our office to reschedule.
```
Why it failed (fill in): 

### tc016 · sms · university · FP (false alarm) · score 51.0
```
Campus Alert: The east parking lot will be closed tomorrow 7am-2pm for maintenance. Use Lot C instead.
```
Why it failed (fill in): 

### tc017 · sms · personal_urgent · FP (false alarm) · score 52.0
```
Mom here. Flight landed early, can you come to the airport now? Terminal B arrivals. Call me.
```
Why it failed (fill in): 

### tc021 · email · bec_invoice · FN (missed scam) · score 46.0
```
From: "Sarah Kim, CFO" <sarah.kim.cfo@outlook.com>
To: student@university.edu
Subject: Urgent wire request
Date: Mon, 9 Nov 2026 10:15:00 -0500
Authentication-Results: mx.university.edu; spf=pass dkim=pass dmarc=pass
Content-Type: text/plain; charset=utf-8

Hi,

I need you to process an urgent wire transfer of $18,400 to a new vendor today. I'm traveling and can't take calls. Please keep this confidential until the deal is announced. Bank details attached.

Sarah
```
Why it failed (fill in): 

### tc022 · email · fake_invoice · FN (missed scam) · score 49.0
```
From: "Geek Squad Billing" <billing@geeksquad-renewals.info>
To: student@university.edu
Subject: Your subscription has been renewed - $399.99
Date: Mon, 9 Nov 2026 10:15:00 -0500
Authentication-Results: mx.university.edu; spf=none dkim=none dmarc=none
Content-Type: text/plain; charset=utf-8

Dear user,

Your annual protection plan was renewed for $399.99. If you did not authorize this charge, call our refund department immediately at +1 (808) 555-0142 to cancel within 24 hours.

Billing Team
```
Why it failed (fill in): 

### tc032 · job_offer · pay_to_work · FN (missed scam) · score 49.0
```
OFFER OF EMPLOYMENT

Dear Candidate,

We are pleased to offer you the position of Junior Software Analyst at Nexora Technologies. Annual salary: $95,000. Before onboarding, please pay a $250 background check and training fee via Zelle to our HR coordinator. Please send a copy of your passport and your SSN for payroll setup.

HR Department
nexora.hr@outlook.com
```
Why it failed (fill in): 

### tc041 · job_offer · rejection · FP (false alarm) · score 50.0
```
Dear Ramya,

Thank you for interviewing for the ML Engineer position at Indeed. After careful consideration, we have decided to move forward with other candidates. We encourage you to apply for future roles at indeed.com/careers.

Indeed Talent Acquisition
talent@indeed.com
```
Why it failed (fill in): 


## rules_only: 8 errors

### tc002 · sms · delivery · FN (missed scam) · score 15.0
```
FedEx: we were unable to deliver parcel #88213. Pay $1.99 redelivery fee at bit.ly/3fdx-pay
```
Evidence given: bit.ly/3fdx-pay uses a link shortener that hides the real destination.
Why it failed (fill in): 

### tc004 · sms · otp_takeover · FN (missed scam) · score 15.0
```
Hi it's Priya, I accidentally sent my verification code to your number, can you send me the 6 digit code please? urgent
```
Evidence given: "urgent" — Creates time pressure so you act before thinking.
Why it failed (fill in): 

### tc005 · sms · toll · FN (missed scam) · score 15.0
```
E-ZPass: You have an unpaid toll balance of $6.85. Pay now to avoid a $50 late fee: https://ezpass-tolls.click/pay
```
Evidence given: ezpass-tolls.click uses the .click ending, which is common in scam sites.
Why it failed (fill in): 

### tc006 · sms · task_job · FN (missed scam) · score 30.0
```
Hello! I'm Jessica from a recruitment agency. Part time remote job, earn $300-$800 per day, no experience needed. Add me on WhatsApp +1 555 0199 to learn more.
```
Evidence given: "WhatsApp" — Moving interviews or conversations to chat apps is a common fake-recruiter tactic. | "no experience needed" — Unusually high pay for little work or no experience.
Why it failed (fill in): 

### tc008 · sms · boss_giftcard · FN (missed scam) · score 45.0
```
Hi, this is Professor Daniels. I'm in a meeting and can't talk. I need you to buy 4 Apple gift cards for a student event, I'll reimburse you. Keep this between us for now.
```
Evidence given: "gift cards" — Requests for gift cards are a classic scam; real organizations never pay or get paid this way. | "Keep this between us" — Asking for secrecy isolates you from people who might spot the scam.
Why it failed (fill in): 

### tc010 · sms · crypto · FN (missed scam) · score 30.0
```
Hey, long time no see! My uncle showed me a crypto platform with guaranteed 30% weekly returns. I can help you set up a wallet, just send USDT to start.
```
Evidence given: "crypto" — Asks for hard-to-reverse payment methods often used by scammers.
Why it failed (fill in): 

### tc022 · email · fake_invoice · FN (missed scam) · score 35.0
```
From: "Geek Squad Billing" <billing@geeksquad-renewals.info>
To: student@university.edu
Subject: Your subscription has been renewed - $399.99
Date: Mon, 9 Nov 2026 10:15:00 -0500
Authentication-Results: mx.university.edu; spf=none dkim=none dmarc=none
Content-Type: text/plain; charset=utf-8

Dear user,

Your annual protection plan was renewed for $399.99. If you did not authorize this charge, call our refund department immediately at +1 (808) 555-0142 to cancel within 24 hours.

Billing Team
```
Evidence given: "immediately" — Creates time pressure so you act before thinking. | "Dear user" — Generic greeting instead of your name. | SPF = none: sender not verified. | DKIM = none: sender not verified.
Why it failed (fill in): 

### tc035 · job_offer · task_scam · FN (missed scam) · score 45.0
```
Hello, I'm Linda from Global Talent Partners. We saw your resume on Indeed. Our client offers a flexible remote job: complete simple app rating tasks and earn commission. You just need to deposit USDT to unlock premium tasks. Contact me on WhatsApp.
```
Evidence given: "USDT" — Asks for hard-to-reverse payment methods often used by scammers. | "WhatsApp" — Moving interviews or conversations to chat apps is a common fake-recruiter tactic.
Why it failed (fill in): 


## llm_only[openai/gpt-oss-20b]: 9 errors

### tc006 · sms · task_job · FN (missed scam) · score nan
```
Hello! I'm Jessica from a recruitment agency. Part time remote job, earn $300-$800 per day, no experience needed. Add me on WhatsApp +1 555 0199 to learn more.
```
Why it failed (fill in): 

### tc012 · sms · otp_genuine · FP (false alarm) · score 85.0
```
Your Google verification code is 482913. Don't share this code with anyone.
```
Evidence given: The message contains only a numeric code and a generic warning, with no official Google branding or contact information | The tone is urgent and instructs not to share the code, a common phishing tactic
Why it failed (fill in): 

### tc013 · sms · delivery · FP (false alarm) · score 85.0
```
Your Amazon package was delivered. Track at https://www.amazon.com/your-orders
```
Evidence given: "Your Amazon package was delivered. Track at https://www.amazon.com/your-orders" lacks a name, order number, or tracking ID | The link points to a generic Amazon URL that is not the usual order tracking format
Why it failed (fill in): 

### tc014 · sms · appointment · FP (false alarm) · score 50.0
```
Reminder: Your dentist appointment with Dr. Lee is on Thursday at 3:30 PM. Reply C to confirm or call our office to reschedule.
```
Evidence given: "Reply C to confirm" is a generic instruction that could be used to harvest replies | "No phone number, address, or official contact details" is a red flag | "Reminder: Your dentist appointment with Dr. Lee" is generic and could be reused by scammers
Why it failed (fill in): 

### tc015 · sms · bank_alert · FP (false alarm) · score 50.0
```
Chase: A charge of $54.20 at TARGET was made on your card ending 4421. If you don't recognize this, call the number on the back of your card.
```
Evidence given: "Chase: A charge of $54.20 at TARGET was made on your card ending 4421." | "If you don't recognize this, call the number on the back of your card." | No official contact details or link are provided.
Why it failed (fill in): 

### tc026 · email · bank_alert · FP (false alarm) · score 85.0
```
From: "Chase" <no.reply.alerts@chase.com>
To: student@university.edu
Subject: Your statement is ready
Date: Mon, 9 Nov 2026 10:15:00 -0500
Authentication-Results: mx.university.edu; spf=pass dkim=pass dmarc=pass
Content-Type: text/plain; charset=utf-8

Your monthly statement for the account ending in 4421 is ready. To view it, sign in to chase.com or the Chase Mobile app. We'll never ask for your password by email.
```
Evidence given: Sender address is no.reply.alerts@chase.com, which is not a typical Chase domain | The message contains no personalized greeting or account details beyond the last four digits | The email states "We'll never ask for your password by email," a common phishing reassurance
Why it failed (fill in): 

### tc037 · job_offer · real_offer · FP (false alarm) · score 50.0
```
Dear Ramya,

Following your interviews with our engineering team on October 21 and 28, we are pleased to offer you the position of Software Engineer I at Microsoft in Redmond, WA. Your offer details are available in our candidate portal. Please review and sign by November 20; the offer expires after that date. Employment is contingent on completing the I-9 and a background check conducted by our vendor after you accept.

Best regards,
Jenna Park, University Recruiting
jenna.park@microsoft.com
```
Evidence given: No link or URL to a candidate portal is provided | The email address is a generic Microsoft domain but no official Microsoft HR signature or branding is present | The offer lacks key details such as salary, benefits, and a formal offer letter
Why it failed (fill in): 

### tc038 · job_offer · recruiter_outreach · FP (false alarm) · score 50.0
```
Hi Ramya, I'm a recruiter at Google. I came across your Cloud-Pilot project on GitHub and think you'd be a great fit for our Associate Cloud Engineer role. If interested, you can apply through careers.google.com and I'll make sure your application is reviewed. Happy to set up a phone screen next week.

Thanks,
David Chen
davidchen@google.com
```
Evidence given: "Hi Ramya, I'm a recruiter at Google" is generic and could be a template | "davidchen@google.com" uses a google.com domain but no unique subdomain | "apply through careers.google.com" is a public link, but no direct link or verification
Why it failed (fill in): 

### tc042 · job_offer · startup_offer · FP (false alarm) · score 50.0
```
Hi Ramya,

Great speaking with you and the team on Friday. As discussed, we'd like to offer you the AI Engineer role at Brightline Labs at $105,000 base. I've attached the formal offer letter; it expires on Nov 18. Let me know if you have questions or want to talk through anything.

Priya Nair, CTO
priya@brightlinelabs.ai
```
Evidence given: No company website or phone number is provided, only an email address | The email is from a single person claiming to be CTO without a corporate signature | The offer letter is attached but no link or reference to a secure portal is given
Why it failed (fill in): 


## agent[openai/gpt-oss-20b]: 1 errors

### tc006 · sms · task_job · FN (missed scam) · score 42.0
```
Hello! I'm Jessica from a recruitment agency. Part time remote job, earn $300-$800 per day, no experience needed. Add me on WhatsApp +1 555 0199 to learn more.
```
Evidence given: "Add me on WhatsApp" – moving the conversation off‑platform is a typical recruiter scam signal | "no experience needed" and "$300-$800 per day" – unusually high pay for minimal work is a red flag | scan_text_signals tool identified both signals with medium severity
Why it failed (fill in): 


## llm_only[openai/gpt-oss-120b]: 7 errors

### tc012 · sms · otp_genuine · FP (false alarm) · score 50.0
```
Your Google verification code is 482913. Don't share this code with anyone.
```
Evidence given: The text provides a numeric verification code and warns not to share it, a common pattern in phishing attempts that try to lure users into revealing the code
Why it failed (fill in): 

### tc013 · sms · delivery · FP (false alarm) · score 50.0
```
Your Amazon package was delivered. Track at https://www.amazon.com/your-orders
```
Evidence given: Unsolicited generic message with no order number or personal details | Link provided without any verification or official Amazon branding
Why it failed (fill in): 

### tc015 · sms · bank_alert · FP (false alarm) · score 50.0
```
Chase: A charge of $54.20 at TARGET was made on your card ending 4421. If you don't recognize this, call the number on the back of your card.
```
Evidence given: The message uses a generic greeting and only shows the last four digits of the card, a common tactic in smishing scams | It instructs you to call the number on the back of the card, a vague direction that could lead to a fraudulent call
Why it failed (fill in): 

### tc028 · email · urgent_legit · FP (false alarm) · score 50.0
```
From: "Microsoft account team" <account-security-noreply@accountprotection.microsoft.com>
To: student@university.edu
Subject: Microsoft account security alert
Date: Mon, 9 Nov 2026 10:15:00 -0500
Authentication-Results: mx.university.edu; spf=pass dkim=pass dmarc=pass
Content-Type: text/plain; charset=utf-8

We detected a sign-in to your account from a new device. If this was you, you can ignore this email. If not, review your recent activity at https://account.microsoft.com/security immediately.
```
Evidence given: The sender address "account-security-noreply@accountprotection.microsoft.com" mimics a Microsoft domain but could be forged | The message contains no personal details and uses a generic greeting | The link provided is to the official Microsoft domain https://account.microsoft.com/security
Why it failed (fill in): 

### tc037 · job_offer · real_offer · FP (false alarm) · score 50.0
```
Dear Ramya,

Following your interviews with our engineering team on October 21 and 28, we are pleased to offer you the position of Software Engineer I at Microsoft in Redmond, WA. Your offer details are available in our candidate portal. Please review and sign by November 20; the offer expires after that date. Employment is contingent on completing the I-9 and a background check conducted by our vendor after you accept.

Best regards,
Jenna Park, University Recruiting
jenna.park@microsoft.com
```
Evidence given: The sender address is "jenna.park@microsoft.com", a legitimate Microsoft domain | The email references specific interview dates and a candidate portal, which are typical of genuine offers
Why it failed (fill in): 

### tc039 · job_offer · interview_invite · FP (false alarm) · score 50.0
```
Hello Ramya,

Thank you for applying to the Data Analyst Intern position at Walmart Global Tech. We'd like to invite you to a 45-minute video interview with the analytics team. Please choose a time slot through the Workday scheduling link in your candidate home page.

Walmart Campus Recruiting
campus.recruiting@walmart.com
```
Evidence given: The sender address uses the official Walmart domain (campus.recruiting@walmart.com) | The message references Workday scheduling, which Walmart commonly uses for interviews | No request for money, passwords, or sensitive personal information is present
Why it failed (fill in): 

### tc042 · job_offer · startup_offer · FP (false alarm) · score 50.0
```
Hi Ramya,

Great speaking with you and the team on Friday. As discussed, we'd like to offer you the AI Engineer role at Brightline Labs at $105,000 base. I've attached the formal offer letter; it expires on Nov 18. Let me know if you have questions or want to talk through anything.

Priya Nair, CTO
priya@brightlinelabs.ai
```
Evidence given: The message references an attached offer letter that isn’t shown, a typical lure in fraudulent job offers | The sender’s email uses a custom domain (brightlinelabs.ai) that can be easily created and may not be verifiable
Why it failed (fill in): 


## agent[openai/gpt-oss-120b]: 5 errors

### tc002 · sms · delivery · FN (missed scam) · score 15.0
```
FedEx: we were unable to deliver parcel #88213. Pay $1.99 redelivery fee at bit.ly/3fdx-pay
```
Evidence given: bit.ly/3fdx-pay uses a link shortener that hides the real destination.
Why it failed (fill in): 

### tc004 · sms · otp_takeover · FN (missed scam) · score 15.0
```
Hi it's Priya, I accidentally sent my verification code to your number, can you send me the 6 digit code please? urgent
```
Evidence given: "urgent" — Creates time pressure so you act before thinking.
Why it failed (fill in): 

### tc005 · sms · toll · FN (missed scam) · score 15.0
```
E-ZPass: You have an unpaid toll balance of $6.85. Pay now to avoid a $50 late fee: https://ezpass-tolls.click/pay
```
Evidence given: ezpass-tolls.click uses the .click ending, which is common in scam sites.
Why it failed (fill in): 

### tc006 · sms · task_job · FN (missed scam) · score 30.0
```
Hello! I'm Jessica from a recruitment agency. Part time remote job, earn $300-$800 per day, no experience needed. Add me on WhatsApp +1 555 0199 to learn more.
```
Evidence given: "WhatsApp" — Moving interviews or conversations to chat apps is a common fake-recruiter tactic. | "no experience needed" — Unusually high pay for little work or no experience.
Why it failed (fill in): 

### tc010 · sms · crypto · FN (missed scam) · score 30.0
```
Hey, long time no see! My uncle showed me a crypto platform with guaranteed 30% weekly returns. I can help you set up a wallet, just send USDT to start.
```
Evidence given: "crypto" — Asks for hard-to-reverse payment methods often used by scammers.
Why it failed (fill in): 
