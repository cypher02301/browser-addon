# Resume ATS Optimizer

A powerful Flask web application that analyzes resumes against job descriptions and provides optimization suggestions to improve ATS (Applicant Tracking System) compatibility.

## 🚀 Features

- **Resume Upload**: Support for PDF and DOCX file formats
- **ATS Compatibility Scoring**: Get a 0-100% compatibility score
- **Keyword Analysis**: Identify missing and matching keywords
- **Optimization Suggestions**: Actionable recommendations for improvement
- **Modern UI**: Beautiful, responsive web interface
- **Synonym Suggestions**: Alternative keywords to improve matching

## 🛠️ Technology Stack

- **Backend**: Flask (Python)
- **Text Processing**: spaCy, NLTK
- **Machine Learning**: scikit-learn (TF-IDF, Cosine Similarity)
- **Document Processing**: PyPDF2, python-docx
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)

## 📋 Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## 🔧 Installation

1. **Clone or download the application files**
   ```bash
   cd ats-optimizer
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install required packages**
   ```bash
   pip install -r requirements.txt
   ```

4. **Download spaCy language model**
   ```bash
   python -m spacy download en_core_web_sm
   ```

## 🚀 Usage

1. **Start the application**
   ```bash
   python app.py
   ```

2. **Open your web browser and navigate to**
   ```
   http://localhost:5000
   ```

3. **Use the application**:
   - Upload your resume (PDF or DOCX format)
   - Paste the job description in the text area
   - Click "Analyze Resume"
   - Review your ATS compatibility score and suggestions

## 📊 How It Works

### ATS Scoring Algorithm

The application uses a sophisticated text analysis approach:

1. **Text Extraction**: Extracts text from PDF/DOCX files
2. **Preprocessing**: Cleans text, removes stop words, performs lemmatization
3. **Vectorization**: Uses TF-IDF (Term Frequency-Inverse Document Frequency)
4. **Similarity Calculation**: Computes cosine similarity between resume and job description
5. **Scoring**: Converts similarity to a 0-100% compatibility score

### Optimization Suggestions

When the score is below 80%, the app provides:

- **Missing Keywords**: Important terms from the job description not found in your resume
- **Section Recommendations**: Suggests adding missing sections (Skills, Experience, etc.)
- **Formatting Tips**: Advice on resume length and structure
- **Quantifiable Achievements**: Prompts to add measurable accomplishments
- **Synonym Alternatives**: Alternative terms for better keyword matching

## 🎯 Score Interpretation

- **80-100%**: Excellent - Your resume is well optimized
- **60-79%**: Good - Room for improvement
- **0-59%**: Needs optimization - Significant improvements required

## 📁 Project Structure

```
ats-optimizer/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # Project documentation
└── templates/
    └── index.html        # Web interface template
```

## 🔍 Key Functions

### Text Processing
- `extract_text()`: Extracts text from PDF/DOCX files
- `preprocess()`: Cleans and normalizes text for analysis

### Analysis
- `calculate_similarity()`: Computes ATS compatibility score
- `get_keyword_analysis()`: Identifies missing and matching keywords
- `generate_suggestions()`: Creates actionable optimization recommendations

### Utilities
- `get_synonyms()`: Finds alternative keywords using WordNet

## 🎨 UI Features

- **Responsive Design**: Works on desktop, tablet, and mobile
- **Modern Styling**: Clean, professional interface with gradients and animations
- **Interactive Elements**: Drag-and-drop file upload, smooth transitions
- **Color-coded Results**: Visual feedback based on score ranges
- **Loading States**: Progress indicators during analysis

## 🛡️ Error Handling

The application includes comprehensive error handling for:
- Unsupported file formats
- Empty files
- Network errors
- Processing failures

## 🔧 Customization

### Adjusting Score Thresholds
Modify the scoring thresholds in `app.py`:
```python
if score < 80:  # Change threshold here
    # Generate suggestions
```

### Adding New File Formats
Extend the `extract_text()` function to support additional formats.

### Modifying Suggestions
Update the `generate_suggestions()` function to add custom recommendation logic.

## 📝 Tips for Best Results

1. **Use Complete Job Descriptions**: Include all sections for accurate analysis
2. **Upload Clean Resumes**: Ensure text is readable and well-formatted
3. **Focus on Keywords**: Pay attention to missing keywords suggestions
4. **Quantify Achievements**: Add specific numbers and percentages
5. **Include Relevant Sections**: Ensure your resume has Skills, Experience, Education sections

## 🤝 Contributing

Feel free to fork this project and submit pull requests for improvements:
- Additional file format support
- Enhanced analysis algorithms
- UI/UX improvements
- Performance optimizations

## 📄 License

This project is open source and available under the MIT License.

## 🆘 Troubleshooting

### Common Issues

1. **spaCy model not found**
   ```bash
   python -m spacy download en_core_web_sm
   ```

2. **File upload errors**
   - Ensure file is PDF or DOCX format
   - Check file size (should be reasonable)
   - Verify file is not corrupted

3. **Low scores despite good resume**
   - Ensure job description is complete
   - Check for keyword variations
   - Consider using synonyms suggested by the app

### Performance Tips

- For large files, processing may take longer
- Ensure stable internet connection for initial setup
- Clear browser cache if experiencing issues

---

**Ready to optimize your resume for ATS success? Start the application and get your compatibility score today!** 🎯