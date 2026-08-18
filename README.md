# 🛡️ Phishing Detection System

Machine Learning (Random Forest) based system jo kisi bhi URL ko check karke batata hai ki woh **Safe** hai ya **Phishing**. Accuracy ~97%.

## 🚀 Live Demo
Deploy karne ke baad yahan apna Streamlit link daal dena.

## 📂 Project Structure
```
phishing-detection/
├── app.py                 # Streamlit web app
├── phishing_model.pkl     # Trained Random Forest model
├── model_columns.json     # Feature columns used by the model
├── safe_sample.json       # Baseline sample row for feature building
├── requirements.txt       # Python dependencies
└── README.md
```

## 🖥️ Run Locally
```bash
git clone https://github.com/<your-username>/Phishing-Detection.git
cd Phishing-Detection
pip install -r requirements.txt
streamlit run app.py
```
Browser mein `http://localhost:8501` khul jayega.

## ☁️ Deploy on Streamlit Cloud (Free)
1. Is poore folder ko GitHub repo mein push karo (neeche steps hain).
2. [share.streamlit.io](https://share.streamlit.io) pe jao aur GitHub se login karo.
3. **New app** click karo.
4. Apna repo select karo, branch `main`, main file `app.py`.
5. **Deploy** click karo — 1-2 minute mein live ho jayega.

## 🧠 Model
- Algorithm: Random Forest Classifier
- Dataset: [GregaVrbancic/Phishing-Dataset](https://github.com/GregaVrbancic/Phishing-Dataset)
- Accuracy: ~96.98%
