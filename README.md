
Email Phishing Detector 

A machine learning-based project to detect phishing emails using Natural Language Processing (NLP) techniques.

  Features

- Detects whether an email is **phishing** or **legitimate**
- Trained using TF-IDF Vectorizer and Logistic Regression
- Simple and user-friendly web interface (Flask)
- Supports local predictions with real-time feedback

 🔧 Technologies Used

- Python 🐍
- Flask 🌐
- Scikit-learn 🤖
- Pandas / NumPy 📊
- HTML & CSS for UI
🚀 How to Run the Project

1. Clone the Repository
   ```bash
   git clone https://github.com/abhi-0308/Email_Phishing_Detector.git
   cd Email_Phishing_Detector


2. Install Dependencies

   ```bash
   pip install -r requirements.txt
   ```
3. Replace areas which requires your api key with your api key from the virustotal website

4. Run the Flask App

   ```bash
   python app.py
   

5. Open in Browser
   Navigate to `http://127.0.0.1:5000/` to use the phishing detection app.

 Project Structure

```
Email_Phishing_Detector/
├── app.py                # Flask web app
├── model.pkl             # Trained ML model
├── vectorizer.pkl        # TF-IDF vectorizer
├── templates/
│   └── index.html        # Web UI
├── static/
│   └── style.css         # Custom styling
├── phishing_dataset.csv  # Dataset used for training
└── README.md             # Project documentation
```

  Dataset

 The model is trained on a labeled dataset of phishing and legitimate emails using TF-IDF features.

 Future Improvements

 Add email header analysis
 Use deep learning (BERT, LSTM)
 Deploy to cloud platforms

 Contributing

Pull requests are welcome! Feel free to open issues or suggest improvements.

  License

This project is open-source and available under the [MIT License](LICENSE).

