from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


# ---------------------------------------------------------
# LOCAL TRAINING DATA
# 0 = Legitimate
# 1 = Scam / Fraud
# ---------------------------------------------------------

TRAINING_DATA = [
    # SCAM EXAMPLES
    ("Urgent! Your bank account has been suspended. Verify immediately.", 1),
    ("Your account will be blocked today. Click the link to verify.", 1),
    ("Share your OTP immediately to complete verification.", 1),
    ("Send your password and OTP to activate your account.", 1),
    ("Congratulations! You won a cash prize. Pay processing fee to claim.", 1),
    ("You have won 50000 rupees cashback. Scan QR and pay 499 fee.", 1),
    ("Lottery winner! Send bank details to receive your prize.", 1),
    ("Pay registration fee to start this work from home job.", 1),
    ("Earn 5000 daily by completing simple online tasks.", 1),
    ("Transfer money now or your account will be permanently blocked.", 1),
    ("Police verification pending. Pay penalty immediately.", 1),
    ("Your KYC has expired. Click this link and enter your OTP.", 1),
    ("Bank security alert. Login now and confirm your password.", 1),
    ("Your debit card is blocked. Verify PIN and CVV immediately.", 1),
    ("Customer support requires your OTP to process the refund.", 1),
    ("Invest today and get guaranteed double returns.", 1),
    ("Guaranteed crypto profit with zero risk. Invest immediately.", 1),
    ("Bitcoin investment will double your money within 24 hours.", 1),
    ("Do not tell anyone about this transaction.", 1),
    ("Keep this confidential and transfer the payment immediately.", 1),
    ("CEO needs you to urgently purchase gift cards.", 1),
    ("Your parcel is held by customs. Pay release fee now.", 1),
    ("Click this link immediately to prevent account suspension.", 1),
    ("Your UPI account will expire. Verify now using this link.", 1),
    ("Scan this QR code to receive your refund.", 1),
    ("Pay a small fee first to receive your reward.", 1),
    ("You are selected for a job. Pay training fee before joining.", 1),
    ("Government subsidy approved. Share OTP to receive payment.", 1),
    ("Your social media account was compromised. Login using this link.", 1),
    ("Final warning! Verify account now or access will be removed.", 1),
    ("Immediate action required. Enter your banking password.", 1),
    ("Claim your free reward before it expires today.", 1),
    ("Send UPI payment now to unlock your cashback.", 1),
    ("Your bank account is under investigation. Send OTP immediately.", 1),
    ("Tech support detected a virus. Pay us to secure your computer.", 1),
    ("Remote support needs your password to repair your account.", 1),
    ("You have been selected as lottery winner. Pay tax first.", 1),
    ("Complete payment immediately to avoid legal action.", 1),
    ("Your SIM will be blocked. Complete KYC using this link.", 1),
    ("Send verification code to customer care immediately.", 1),

    # LEGITIMATE EXAMPLES
    ("Your order has been shipped and will arrive tomorrow.", 0),
    ("Your monthly bank statement is now available in the official app.", 0),
    ("Meeting scheduled for tomorrow at 10 AM.", 0),
    ("Please submit your assignment before Friday.", 0),
    ("Your electricity bill for this month has been generated.", 0),
    ("Your package has been delivered successfully.", 0),
    ("Welcome to our service. Your account was created successfully.", 0),
    ("Your appointment is confirmed for Monday.", 0),
    ("The college will remain closed tomorrow.", 0),
    ("Your exam timetable has been published on the college portal.", 0),
    ("Thank you for your purchase. Here is your order confirmation.", 0),
    ("Your refund has been processed to the original payment method.", 0),
    ("Your flight booking has been confirmed.", 0),
    ("Your subscription will renew next month.", 0),
    ("Please join the team meeting using the official company calendar.", 0),
    ("Your salary has been credited to your account.", 0),
    ("Your attendance report is available on the student portal.", 0),
    ("Your library book is due next week.", 0),
    ("The project presentation starts at 2 PM tomorrow.", 0),
    ("Your food order is being prepared.", 0),
    ("Your train ticket has been confirmed.", 0),
    ("The software update was installed successfully.", 0),
    ("Your password was changed successfully.", 0),
    ("Your support request has been received.", 0),
    ("The workshop registration is confirmed.", 0),
    ("Your course certificate is ready to download from the portal.", 0),
    ("Your payment receipt is available in the official app.", 0),
    ("Your professor has uploaded new lecture notes.", 0),
    ("The interview has been scheduled for Tuesday afternoon.", 0),
    ("Your application has been received successfully.", 0),
    ("Your delivery is expected between 2 PM and 4 PM.", 0),
    ("The event begins tomorrow morning.", 0),
    ("Your reservation has been confirmed.", 0),
    ("Your account profile was updated successfully.", 0),
    ("The university has published the semester results.", 0),
    ("Your invoice is attached for your records.", 0),
    ("The team has shared the updated project document.", 0),
    ("Your mobile recharge was completed successfully.", 0),
    ("Your class has been moved to room 204.", 0),
    ("The maintenance window is scheduled for Sunday.", 0),
]


texts = [item[0] for item in TRAINING_DATA]
labels = [item[1] for item in TRAINING_DATA]


# ---------------------------------------------------------
# TF-IDF + LOGISTIC REGRESSION ML PIPELINE
# ---------------------------------------------------------

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            random_state=42
        )
    )
])


# Train local classifier
model.fit(texts, labels)


# ---------------------------------------------------------
# PREDICTION FUNCTION
# ---------------------------------------------------------

def predict_scam_probability(text):
    """
    Returns scam probability from 0.0 to 1.0.
    """

    if not text or not text.strip():
        return 0.0

    probability = model.predict_proba(
        [text]
    )[0][1]

    return float(probability)


def get_ml_result(text):
    """
    Returns probability, percentage and simple ML label.
    """

    probability = predict_scam_probability(text)

    percentage = round(
        probability * 100,
        1
    )

    if probability >= 0.75:
        label = "High ML scam likelihood"

    elif probability >= 0.55:
        label = "Moderate ML scam likelihood"

    else:
        label = "Low ML scam likelihood"

    return {
        "probability": probability,
        "percentage": percentage,
        "label": label
    }