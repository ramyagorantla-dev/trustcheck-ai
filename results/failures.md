# Failure analysis

Every misclassified example, per system. FN = scam marked safe (the dangerous error); FP = genuine message flagged.


## classic_tfidf_lr: 11 errors

### tc004 · sms · otp_takeover · FN (missed scam) · score 46
```
Hi it's Priya, I accidentally sent my verification code to your number, can you send me the 6 digit code please? urgent
```
Why it failed (fill in): 

### tc010 · sms · crypto · FN (missed scam) · score 49
```
Hey, long time no see! My uncle showed me a crypto platform with guaranteed 30% weekly returns. I can help you set up a wallet, just send USDT to start.
```
Why it failed (fill in): 

### tc012 · sms · otp_genuine · FP (false alarm) · score 52
```
Your Google verification code is 482913. Don't share this code with anyone.
```
Why it failed (fill in): 

### tc013 · sms · delivery · FP (false alarm) · score 51
```
Your Amazon package was delivered. Track at https://www.amazon.com/your-orders
```
Why it failed (fill in): 

### tc014 · sms · appointment · FP (false alarm) · score 50
```
Reminder: Your dentist appointment with Dr. Lee is on Thursday at 3:30 PM. Reply C to confirm or call our office to reschedule.
```
Why it failed (fill in): 

### tc016 · sms · university · FP (false alarm) · score 51
```
Campus Alert: The east parking lot will be closed tomorrow 7am-2pm for maintenance. Use Lot C instead.
```
Why it failed (fill in): 

### tc017 · sms · personal_urgent · FP (false alarm) · score 52
```
Mom here. Flight landed early, can you come to the airport now? Terminal B arrivals. Call me.
```
Why it failed (fill in): 

### tc021 · email · bec_invoice · FN (missed scam) · score 46
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

### tc022 · email · fake_invoice · FN (missed scam) · score 49
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

### tc032 · job_offer · pay_to_work · FN (missed scam) · score 49
```
OFFER OF EMPLOYMENT

Dear Candidate,

We are pleased to offer you the position of Junior Software Analyst at Nexora Technologies. Annual salary: $95,000. Before onboarding, please pay a $250 background check and training fee via Zelle to our HR coordinator. Please send a copy of your passport and your SSN for payroll setup.

HR Department
nexora.hr@outlook.com
```
Why it failed (fill in): 

### tc041 · job_offer · rejection · FP (false alarm) · score 50
```
Dear Ramya,

Thank you for interviewing for the ML Engineer position at Indeed. After careful consideration, we have decided to move forward with other candidates. We encourage you to apply for future roles at indeed.com/careers.

Indeed Talent Acquisition
talent@indeed.com
```
Why it failed (fill in): 


## rules_only: 8 errors

### tc002 · sms · delivery · FN (missed scam) · score 15
```
FedEx: we were unable to deliver parcel #88213. Pay $1.99 redelivery fee at bit.ly/3fdx-pay
```
Evidence given: bit.ly/3fdx-pay uses a link shortener that hides the real destination.
Why it failed (fill in): 

### tc004 · sms · otp_takeover · FN (missed scam) · score 15
```
Hi it's Priya, I accidentally sent my verification code to your number, can you send me the 6 digit code please? urgent
```
Evidence given: "urgent" — Creates time pressure so you act before thinking.
Why it failed (fill in): 

### tc005 · sms · toll · FN (missed scam) · score 15
```
E-ZPass: You have an unpaid toll balance of $6.85. Pay now to avoid a $50 late fee: https://ezpass-tolls.click/pay
```
Evidence given: ezpass-tolls.click uses the .click ending, which is common in scam sites.
Why it failed (fill in): 

### tc006 · sms · task_job · FN (missed scam) · score 30
```
Hello! I'm Jessica from a recruitment agency. Part time remote job, earn $300-$800 per day, no experience needed. Add me on WhatsApp +1 555 0199 to learn more.
```
Evidence given: "WhatsApp" — Moving interviews or conversations to chat apps is a common fake-recruiter tactic. | "no experience needed" — Unusually high pay for little work or no experience.
Why it failed (fill in): 

### tc008 · sms · boss_giftcard · FN (missed scam) · score 45
```
Hi, this is Professor Daniels. I'm in a meeting and can't talk. I need you to buy 4 Apple gift cards for a student event, I'll reimburse you. Keep this between us for now.
```
Evidence given: "gift cards" — Requests for gift cards are a classic scam; real organizations never pay or get paid this way. | "Keep this between us" — Asking for secrecy isolates you from people who might spot the scam.
Why it failed (fill in): 

### tc010 · sms · crypto · FN (missed scam) · score 30
```
Hey, long time no see! My uncle showed me a crypto platform with guaranteed 30% weekly returns. I can help you set up a wallet, just send USDT to start.
```
Evidence given: "crypto" — Asks for hard-to-reverse payment methods often used by scammers.
Why it failed (fill in): 

### tc022 · email · fake_invoice · FN (missed scam) · score 35
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

### tc035 · job_offer · task_scam · FN (missed scam) · score 45
```
Hello, I'm Linda from Global Talent Partners. We saw your resume on Indeed. Our client offers a flexible remote job: complete simple app rating tasks and earn commission. You just need to deposit USDT to unlock premium tasks. Contact me on WhatsApp.
```
Evidence given: "USDT" — Asks for hard-to-reverse payment methods often used by scammers. | "WhatsApp" — Moving interviews or conversations to chat apps is a common fake-recruiter tactic.
Why it failed (fill in): 
