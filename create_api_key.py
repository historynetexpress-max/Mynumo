import secrets
import hashlib
import hmac
from datetime import datetime

def generate_api_key(prefix="sk", length=32):
    """
    एक सुरक्षित API Key जनरेट करें।
    
    :param prefix: Key के आगे लगने वाला प्रीफिक्स (जैसे 'sk' या 'test')
    :param length: रैंडम भाग की बाइट्स की संख्या (जितनी ज्यादा, उतनी सुरक्षित)
    :return: स्ट्रिंग के रूप में API Key
    """
    # क्रिप्टोग्राफिक रूप से सुरक्षित रैंडम बाइट्स जनरेट करें और उन्हें URL-safe base64 में बदलें
    random_part = secrets.token_urlsafe(length)
    
    # टाइमस्टैम्प (वैकल्पिक) जोड़ सकते हैं
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    
    # प्रीफिक्स के साथ Key बनाएँ
    api_key = f"{prefix}_{timestamp}_{random_part}"
    return api_key

def hash_api_key(api_key, secret_salt=None):
    """
    API Key को हैश करके स्टोर करने के लिए (सुरक्षा हेतु)
    """
    if secret_salt is None:
        secret_salt = secrets.token_hex(16)  # या कोई निश्चित सॉल्ट
    hashed = hmac.new(
        key=secret_salt.encode('utf-8'),
        msg=api_key.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    return hashed, secret_salt

# उदाहरण उपयोग
if __name__ == "__main__":
    # नई API Key जनरेट करें
    new_key = generate_api_key(prefix="myapp", length=32)
    print("Generated API Key:", new_key)
    
    # हैश बनाएँ (डेटाबेस में स्टोर करने के लिए)
    hashed_key, salt = hash_api_key(new_key)
    print("Hashed Key:", hashed_key)
    print("Salt used:", salt)
    
    # सुझाव: असली उपयोग में हैश और सॉल्ट को डेटाबेस में रखें, और Key को यूजर को दें।