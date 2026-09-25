"""Generate the Philippines-specific SMS augmentation dataset.

The public UCI SMS Spam Collection is almost entirely UK/US English and
misses the scam patterns that actually circulate in the Philippines
(GCash/PayMaya "account locked" phishing, fake courier COD fees, SIM
registration scams, lotto/raffle scams, etc.), while legitimate PH text
traffic is heavily Taglish. Without local examples, a model trained only
on the UCI set tends to key off surface features ("mentions money/a
brand") rather than the real signal (urgency + a link + a request for
credentials/OTP), and it has no chance of recognizing PH-specific lures
at all.

Every message below is synthetic: written from scratch to mirror publicly
reported scam formats (BSP/NTC/DICT consumer advisories, GCash's own
"Konsult" scam-awareness posts, news coverage). No real phone numbers,
account numbers, names, or links are used. Running this script regenerates
data/raw/ph_scam_augmentation.csv deterministically.
"""

import csv
from pathlib import Path

SPAM = [
    # --- GCash / e-wallet phishing ---
    "GCash Alert: Your account has been flagged for unusual activity. Verify now to avoid suspension: bit.ly/gcash-verify123",
    "Your GCash account will be permanently disabled in 24 hours due to policy violation. Update your info here: gcash-secure.info/verify",
    "[GCash] Suspicious login detected from Davao. If this was not you, secure your account immediately: gcsh-support.com/lock",
    "Congratulations! Your GCash account is eligible for a P5,000 cashback promo. Claim now before it expires: gcash-promo2024.net",
    "URGENT: GCash detected a problem with your account. Reply with your MPIN to confirm your identity or your account will be closed.",
    "Your GCash is temporarily locked. Click link and login para ma-verify account mo agad: gcash-unlock.ph",
    "GCash Official: We noticed unauthorized access sa account mo. I-send ang OTP na natanggap mo para ma-secure namin ito.",
    "PayMaya Notice: Your account has a pending security check. Failure to verify within 12 hrs will result in permanent deactivation. paymaya-verify.co",
    "[PayMaya] You have received P8,500 pending transfer. Claim your funds by confirming your account details at paymaya-claim.net",
    "Maya Alert: Bawal na gamitin ang account mo hanggat hindi mo na-verify. I-click ang link at ilagay ang buong impormasyon: maya-securelink.info",
    "GCash: Na-detect namin na may nag-attempt mag-login gamit account mo. I-send agad ang 6-digit code para ma-block namin sila.",
    "Your GCash has been selected for a free P2000 load. Kindly confirm by sending your GCash number and OTP to claim.",
    # --- Bank impersonation ---
    "BDO Alert: Your online banking access has been suspended due to security concerns. Verify your account: bdo-secure-access.com",
    "BPI Notice: Unusual transaction detected on your account. Please confirm your identity immediately at bpi-verify-account.net or your card will be blocked.",
    "METROBANK: Your debit card has been temporarily deactivated. Update your details now to reactivate: metrobank-cardupdate.info",
    "UnionBank Security Team: We detected a login attempt from an unrecognized device. Verify here within 1 hour: unionbank-secure.co",
    "Your Landbank account is under review for suspicious activity. Failure to respond within 24 hours will lead to account closure. Click: landbank-verify.net",
    "[BDO] Your account balance is on hold. Complete verification to unlock your funds: bdo-online-verify.com/secure",
    "Security Alert from your bank: Someone tried to access your account from Cebu. Confirm it's not you by entering your OTP here: bank-alert-ph.com",
    # --- Courier / parcel scams ---
    "J&T Express: Your parcel is on hold due to unpaid customs fee of P150. Settle now to avoid return to sender: jtexpress-fee.info",
    "LBC Notification: Your package could not be delivered due to incomplete address. Update your info and pay P99 redelivery fee: lbc-redeliver.net",
    "Flash Express: Your parcel is stuck at the warehouse. Pay the outstanding P120 handling fee within 24hrs or it will be discarded: flashexpress-pay.co",
    "Ninja Van: We attempted to deliver your parcel but no one was home. Reschedule and pay P80 fee here: ninjavan-reschedule.info",
    "Your parcel from abroad is being held by customs. Pay the P350 release fee immediately to avoid confiscation: customs-release-ph.net",
    "J&T: May hindi pa nabayarang shipping fee ang parcel mo. I-settle na para hindi ma-cancel ang delivery: jt-billing.info/pay",
    # --- Lotto / raffle / prize scams ---
    "CONGRATULATIONS! Your number has been selected as the lucky winner of P950,000 in the GMA raffle promo. Claim now: gma-raffle-claim.net",
    "You have won a brand new iPhone 15 from Globe's anniversary raffle! Claim your prize by providing your details here: globe-raffle-prize.com",
    "PCSO Lotto Notice: Your ticket number matched the jackpot draw. Contact our claims officer immediately to process your P5,000,000 winnings.",
    "SM Malls 30th Anniversary Promo: You are our lucky winner of P100,000 GCash! Claim before the deadline: sm-anniv-promo.net",
    "Congrats! Na-pick ang number mo bilang panalo sa Piso Pay raffle. I-claim ang premyo mo dito bago mag-expire: pisopay-winner.info",
    "Jollibee 45th Anniversary: You won a free Family Bucket plus P20,000 cash. Click to claim within 24 hours: jollibee-promo-win.net",
    # --- Telco / load / promo scams ---
    "Globe: Congratulations! You are entitled to a FREE 999 load. Click here to claim before it expires: globe-freeload.net",
    "Smart Padala: Your number was randomly selected to receive P500 free load. Claim now: smart-loadpromo.info",
    "TNT Load Promo: I-forward mo lang ang message na ito sa 5 contacts para makakuha ka ng libreng 50 load.",
    "DITO Telecom: You've been chosen for a free 5GB data promo. Register your details here to activate: dito-freedata.net",
    # --- SIM registration scam (real 2022-2023 PH wave) ---
    "NTC Advisory: Failure to register your SIM within 24 hours will result in permanent deactivation. Register now at ntc-simregister.info",
    "Your SIM registration is incomplete. I-update ang detalye mo dito para hindi ma-block ang number mo: sim-register-ph.net",
    "URGENT: SIM Registration Act deadline is today. Click to complete your registration or lose your number permanently: simcard-verify.info",
    # --- OTP / credential phishing (generic) ---
    "Your one-time PIN is required to prevent unauthorized access. Reply with the 6-digit code sent to your phone within 5 minutes.",
    "This is your bank calling. We need to verify your identity, please provide the OTP you just received to cancel the fraudulent transaction.",
    "Security Team: Someone is trying to access your account right now. Send us the verification code immediately to stop them.",
    "Para ma-secure ang account mo, i-send ang OTP na natanggap mo sa amin ngayon din. Huwag ibahagi ito sa iba maliban sa amin.",
    # --- Job / work-from-home scams ---
    "Kumita ng P3,000-5,000 daily sa online part-time job! Simple lang, product testing. Message us now para mag-apply: t.me/phjobph",
    "URGENT HIRING: Work from home, no experience needed, P800/day guaranteed. Register here to start today: wfh-hiring-ph.net",
    "Online Encoder needed, P1200 per day, pwedeng part time lang. I-reply ang 'YES' para sa job details at registration fee.",
    "Data Entry Job Alert: Earn P25,000/month working from your phone. Limited slots! Apply now: easyjob-ph.info",
    # --- Loan app scams ---
    "Pre-approved ka na for a P50,000 loan with 0% interest! I-claim mo na agad bago mag-expire ang offer: fastcash-loan.net",
    "CashCredit PH: Your loan application has been approved. Send your bank details to process the P30,000 release today.",
    "May available ka na cash loan na P20,000, walang collateral, walang requirements. Mag-apply na dito: quickloan-approved.info",
    # --- Investment / romance scam style ---
    "Invest P5,000 today and earn P50,000 in just 7 days guaranteed! Join our trading group now: t.me/investfastph",
    "Hi bebe, I miss you. I need P10,000 lang for emergency, ipapadala ko rin sayo pagbalik ko galing abroad. Please help me today.",
    "Crypto opportunity: Double your money in 48 hours guaranteed! Limited slots available, message now to reserve yours.",
    # --- Utility bill phishing ---
    "MERALCO: Your electric bill is overdue. Failure to settle within 24 hours will result in disconnection. Pay here: meralco-billpay.net",
    "PLDT Notice: Your account balance is past due. Avoid service interruption, settle now: pldt-payment-portal.info",
    "Maynilad: Unpaid water bill detected on your account. Settle immediately to avoid disconnection: maynilad-pay.co",
]

HAM = [
    # --- Legit e-wallet / bank notifications (informational, no link/urgency) ---
    "You have received P500.00 from Juan Dela Cruz via GCash. Your reference number is 1234567890. Thank you for using GCash!",
    "GCash: You have successfully paid P1,250.00 to Meralco. Your new balance is P3,420.15.",
    "BDO: A debit transaction of P2,000.00 was posted to your account ending in 4521 on 09/12. If you did not authorize this, call our hotline.",
    "Your BPI account ending 8890 was credited P15,000.00 salary from ABC Corp on 09/25.",
    "PayMaya: Your cash-in of P1,000.00 was successful. Available balance: P4,320.00.",
    "Reminder: Your Metrobank credit card statement balance of P4,500 is due on Oct 5. Minimum amount due is P450.",
    # --- Family / friends casual chat ---
    "Hoy tara later after work, kain tayo sa may Katipunan. Sabi ni Ana gusto rin niya sumama.",
    "Nasaan ka na? Hinihintay ka na namin dito sa terminal, mag-ingat sa biyahe ha.",
    "Happy birthday ate! Sana pumunta ka mamaya sa bahay, magluluto kami ng spaghetti at may cake pa.",
    "Uy pasensya na di ako nakasagot kanina, may meeting kasi ako buong umaga. Ano ba kailangan mo?",
    "Pauwi na ako, sabay tayo mamaya sa jeep stop malapit sa palengke.",
    "Kamusta lola? Sana okay ka lang dyan sa probinsya, ingat lagi at uwi ako next month.",
    "Grabe ang ulan dito sa amin, ingat ka sa biyahe pauwi mamaya. Text mo lang ako pag nasa bahay ka na.",
    "Pare, may extra ticket ako sa concert this weekend, gusto mo sumama? Libre ko na lang travel mo.",
    "Nakuha mo na ba yung binili kong gamot sa parents mo? Sabihin mo sakin kung magkano yung nagastos mo.",
    "Ok lang ba kung mamaya na lang tayo mag-usap? Kasi busy pa ako ngayon sa trabaho.",
    # --- School/work messages ---
    "Reminder: Submission ng project ay bukas na, 5PM deadline. I-send niyo sa group chat ang files niyo.",
    "Good morning class, wala tayong meeting mamaya dahil may faculty meeting. Makikita niyo na lang sa Monday ang schedule natin.",
    "Hi, this is to confirm your job interview on Monday, Sept 29 at 10AM at our Makati office. Please bring 2 valid IDs.",
    "Team, please submit your weekly report by end of day. Let me know if you need an extension.",
    "Your enrollment for the 2nd semester has been confirmed. Please check the student portal for your class schedule.",
    "Meeting moved to 3PM today instead of 2PM, same Zoom link. See you all later.",
    # --- Legit delivery/appointment ---
    "Your Lazada order #PH20394857 has been shipped and is expected to arrive within 3-5 business days.",
    "Grab: Your driver Mark is arriving in 3 minutes, plate number ABC1234, Toyota Vios white.",
    "This is a reminder of your dental appointment tomorrow at 2PM. Please arrive 10 minutes early. Call us if you need to reschedule.",
    "Your Shopee package has arrived at the pickup station. Please claim within 3 days using your order number.",
    "Foodpanda: Your order has been picked up by the rider and is on its way. Estimated arrival: 15 minutes.",
    # --- Everyday Taglish chit-chat ---
    "Try mo yung bagong resto sa may Ortigas, masarap yung sisig nila at di naman mahal.",
    "Wag ka na mag-alala sa project, tinulungan ko na yung groupmate natin ayusin yung slides.",
    "May sale daw sa mall ngayon, gusto mo sumama mamaya? Baka may makuha tayong maganda.",
    "Salamat sa tulong mo kanina ha, nakauwi na ako ng maayos. Ingat ka rin palagi.",
    "Kumusta na yung lagnat mo? Uminom ka ng gamot at magpahinga, wag ka muna lumabas.",
    "Sige, kita tayo bukas ng 9AM sa coffee shop malapit sa office, sasabay na lang ako sayo.",
    "Natapos ko na yung report, i-che-check ko lang ulit bago ko ipasa sayo mamaya.",
    "Ingat sa biyahe pauwi, sabihan mo lang ako pag nasa bahay ka na para di ako mag-alala.",
    "May pasalubong ako sayo galing probinsya, punta ka lang bahay namin mamaya para kunin mo.",
    "Wag mo kalimutan dalhin yung payong, ulan daw sa weather forecast mamaya ng hapon.",
    # --- Legit promo (opt-in style, not urgent/credential-seeking) ---
    "Globe: Enjoy unlimited calls and texts to all networks with GoUNLI30. Dial *143# to subscribe. Terms apply.",
    "Smart: You are currently enrolled in GigaSurf50, valid for 3 days. Remaining data balance: 1.2GB.",
    "Thank you for subscribing to SMART LOAD ALL 20. Your promo will expire in 7 days.",
]

def main():
    rows = [("label", "text")]
    rows += [("spam", t) for t in SPAM]
    rows += [("ham", t) for t in HAM]

    out_path = Path(__file__).resolve().parent.parent / "data" / "raw" / "ph_scam_augmentation.csv"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    print(f"Wrote {len(rows) - 1} rows ({len(SPAM)} spam, {len(HAM)} ham) to {out_path}")


if __name__ == "__main__":
    main()
