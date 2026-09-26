"""Generate the international (non-PH) SMS scam augmentation dataset.

The UCI SMS Spam Collection is UK-centric and mostly from the mid-2000s
(premium-rate subscription traps, ringtone services). It misses scam
formats that are common internationally today: USPS/FedEx/DHL "unpaid fee"
parcel scams, PayPal/bank "account locked" phishing, IRS/HMRC tax scams,
E-ZPass/toll-road smishing (a large current wave in the US), and fake
Netflix/Apple ID subscription renewals. This file adds those patterns so
the model isn't tied to one country's (or one decade's) scam vocabulary.

Every message is synthetic, written from scratch to mirror publicly
reported scam formats (FTC/FCC consumer advisories, bank/courier
fraud-awareness pages, news coverage). No real phone numbers, account
numbers, names, or working links are used.
"""

import csv
from pathlib import Path

SPAM = [
    # --- Courier / parcel scams (US/UK/EU/AU/CA) ---
    "USPS: Your package has a $2.99 unpaid customs fee. Please pay immediately to avoid return to sender: usps-fee-pay.com",
    "FedEx: We could not deliver your parcel due to an incomplete address. Update your details within 24 hours: fedex-redeliver.info",
    "DHL Express: Your parcel is on hold at customs. Pay the outstanding fee of $3.50 to release it: dhl-clearance.net",
    "Royal Mail: Your item could not be delivered as the postage was insufficient. Pay 1.99 GBP to schedule redelivery: royalmail-redelivery.co",
    "Evri: We attempted delivery but no one was available. Reschedule and confirm your address: evri-reschedule.info",
    "Canada Post: Your parcel is being held due to an unpaid duty fee of $4.25. Settle now to avoid return: canadapost-fee.net",
    "Australia Post: Your parcel could not be delivered. A small redelivery fee is required, pay here: auspost-redeliver.info",
    "Your Amazon package delivery failed. Confirm your address and payment details to reschedule: amazon-redelivery-help.com",
    # --- Bank / payment app impersonation ---
    "Chase: We noticed unusual activity on your account. Verify your identity now or your card will be suspended: chase-verify-now.com",
    "Wells Fargo Alert: Your online banking has been locked due to suspicious login. Restore access here: wellsfargo-secure-login.net",
    "Bank of America: Your debit card has been temporarily deactivated. Confirm your details to reactivate: bofa-cardupdate.info",
    "Barclays: A payment of £450 was attempted on your account. If this wasn't you, verify your identity immediately: barclays-alert.co",
    "HSBC Security: Unusual sign-in detected. Confirm it's you within 1 hour or we will restrict your account: hsbc-confirm.net",
    "NatWest: Your online banking session has expired for security reasons. Log in again to restore access: natwest-relogin.info",
    "PayPal: We limited your account due to unusual activity. Verify your information to remove the limitation: paypal-limitation-fix.com",
    "PayPal Alert: You sent a payment of $250.00. If you did not authorize this, click here to dispute now: paypal-dispute-now.net",
    "Venmo: Your account has a pending security review. Confirm your identity within 24 hours or funds will be frozen: venmo-review.info",
    "Zelle: Your transfer of $500 is on hold. Verify your bank details to release the funds: zelle-verify-transfer.com",
    "Revolut: Suspicious activity was detected on your card. Confirm your identity now to avoid account suspension: revolut-secure.net",
    "Cash App: Your account has been flagged. Confirm your details within 24 hours to avoid permanent suspension: cashapp-confirm.info",
    # --- Telco impersonation ---
    "AT&T: Your bill payment failed. Update your payment method now to avoid service interruption: att-billpay.info",
    "Verizon: Your account is past due. Avoid disconnection by settling your balance today: verizon-paynow.net",
    "T-Mobile: Your SIM card requires urgent verification or your service will be suspended within 24 hours: tmobile-simverify.com",
    "Vodafone: You have a pending bill of £35.00. Pay now to avoid service suspension: vodafone-pay.info",
    # --- Tax authority scams ---
    "IRS: You are eligible for a tax refund of $850. Claim it now by verifying your bank details: irs-refund-claim.com",
    "IRS Notice: Your tax return has an issue that requires immediate action. Failure to respond will result in legal action: irs-gov-alert.net",
    "HMRC: You are due a tax refund of £215.68. Click here to request the transfer: hmrc-taxrefund.info",
    "HMRC Final Notice: Outstanding tax payment detected. Settle immediately to avoid enforcement action: hmrc-payment-due.com",
    # --- Toll road scams (very common current smishing wave) ---
    "E-ZPass: You have an unpaid toll of $6.99. Pay now to avoid a $50 late fee and driving record impact: ezpass-tollpay.com",
    "FasTrak: Your toll account balance is past due. Settle now to avoid penalties: fastrak-billing.info",
    "SunPass Toll Notice: Unpaid toll balance detected. Pay immediately to avoid suspension of your account: sunpass-pay.net",
    "Final Notice: You have an unpaid toll violation. Pay the $12.50 fee within 7 days to avoid additional fees: toll-violation-payment.com",
    # --- Subscription / tech impersonation ---
    "Netflix: Your payment method has failed. Update your billing details now to avoid losing access: netflix-billing-update.com",
    "Apple ID: Your account has been locked due to suspicious activity. Verify now to restore access: apple-id-verify.net",
    "iCloud Alert: Your storage is full and your account is at risk of suspension. Verify your Apple ID here: icloud-storage-alert.info",
    "Amazon Prime: Your membership payment could not be processed. Update your card details to avoid cancellation: amazon-prime-billing.com",
    "Microsoft Security Alert: We detected unusual sign-in activity on your account. Verify now to prevent lockout: microsoft-alert-verify.net",
    "Your Disney+ subscription payment failed. Update your billing info within 24 hours to keep your account active: disneyplus-billing.info",
    # --- Messaging / social media ---
    "WhatsApp: Your account will be suspended in 24 hours due to a policy violation. Verify here to prevent this: whatsapp-verify-account.com",
    "Facebook Security: We noticed a login attempt from a new device. Confirm your identity or your account will be locked: fb-secure-check.net",
    # --- Crypto / investment scams ---
    "Coinbase: Unusual withdrawal attempt detected on your account. Secure your funds now by verifying your identity: coinbase-secure.net",
    "Binance: Your account has been selected for a security upgrade. Verify your details within 24 hours to avoid suspension: binance-verify.info",
    "Invest just $200 today and earn $2,000 in a week, guaranteed! Limited spots, message now to join: t.me/investfastglobal",
    # --- Generic prize / lottery ---
    "CONGRATULATIONS! You've won a $1,000 Walmart gift card. Claim your prize now before it expires: walmart-giftcard-win.com",
    "You have been selected to receive a free iPhone 15 Pro. Claim your prize within 24 hours: apple-prize-claim.net",
    "National Lottery: Your number matched our weekly draw. Contact our claims department immediately to receive your winnings.",
    # --- Job / work-from-home scams ---
    "URGENT HIRING: Earn $500/day working from home, no experience required. Apply now, limited slots available: wfh-hiring-global.net",
    "Data Entry Job: Earn $3000/month working from your phone. Register today to secure your spot: easyjob-global.info",
]

HAM = [
    # --- Legit bank / payment notifications ---
    "Chase: A payment of $45.20 was made at Target on 09/20. If you did not make this purchase, call the number on your card.",
    "Your Wells Fargo account ending in 4521 was credited $1,200.00 on 09/22.",
    "PayPal: You sent $30.00 to Alex Johnson. Your new balance is $145.60.",
    "Venmo: John paid you $20.00 for dinner last night.",
    "Barclays: Your monthly statement is now available to view in the app.",
    "Reminder: Your Capital One credit card payment of $85.00 is due on Oct 3.",
    # --- Legit delivery notifications ---
    "Your Amazon order #112-7789456 has shipped and will arrive Thursday by 8pm.",
    "USPS: Your package is out for delivery and should arrive by end of day.",
    "FedEx: Your package was delivered to your front door at 2:14pm today.",
    "DHL: Your shipment has cleared customs and is on its way to the delivery depot.",
    # --- Legit telco / subscription ---
    "Verizon: You have used 80% of your monthly data. Your billing cycle resets on the 1st.",
    "Netflix: Your next billing date is October 5. Manage your subscription anytime in account settings.",
    "T-Mobile: Thank you for your payment of $70.00. Your service is active.",
    # --- Appointments / work / school ---
    "Reminder: Your dentist appointment is tomorrow at 10:30am. Reply C to confirm or call us to reschedule.",
    "This is to confirm your interview on Tuesday at 2pm at our downtown office. Please bring a copy of your resume.",
    "Team meeting moved to 4pm today, same conference room. See you there.",
    "Your prescription is ready for pickup at the pharmacy. Hours are 9am-7pm today.",
    "Your flight AA1234 departs at 6:45am tomorrow. Check-in opens 24 hours before departure.",
    # --- Casual chat ---
    "Hey, are we still on for coffee tomorrow morning? Let me know what time works.",
    "Thanks for helping me move this weekend, I owe you a favor big time.",
    "Running about 10 minutes late, traffic is bad on the highway. See you soon.",
    "Can you grab milk on your way home? We're almost out.",
    "Happy birthday! Hope you have an amazing day, let's celebrate this weekend.",
    "Just landed, will call you once I get to the hotel and settle in.",
    "Don't forget we have book club tonight at 7, same place as last time.",
    "The game starts at 8, want to watch it together at my place?",
    "Your Uber is arriving now, look for a silver Camry, license plate 7XKT492.",
    "Reminder: recycling pickup is tomorrow morning, put the bins out tonight.",
    "Great seeing you today, let's catch up again soon, maybe next week?",
    "Your gym class starts at 6pm, see you on the mat.",
    "The plumber said he'll be there between 1 and 3pm tomorrow.",
    "Loved the photos from the trip, can you send me a few more?",
    "Your library books are due back on Friday, you can renew online if needed.",
    "Quick reminder that rent is due on the 1st, let me know if you need the account details again.",
]


def main():
    rows = [("label", "text")]
    rows += [("spam", t) for t in SPAM]
    rows += [("ham", t) for t in HAM]

    out_path = Path(__file__).resolve().parent.parent / "data" / "raw" / "international_scam_augmentation.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    print(f"Wrote {len(rows) - 1} rows ({len(SPAM)} spam, {len(HAM)} ham) to {out_path}")


if __name__ == "__main__":
    main()
