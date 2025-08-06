"""
ATS OPTIMIZATION APP
This app analyzes resumes against job descriptions and provides optimization suggestions.
Features:
1. Upload PDF/DOCX resume and paste job description
2. Calculate ATS compatibility score (0-100%)
3. Get specific improvement suggestions if score < 80%
4. View keyword matching analysis
"""

from flask import Flask, render_template, request, jsonify
import tempfile
import os
import re
import spacy
from PyPDF2 import PdfReader
from docx import Document
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from nltk.corpus import wordnet
import nltk
nltk.download('wordnet')

app = Flask(__name__)
nlp = spacy.load("en_core_web_sm")

def extract_text(file):
    """Extract text from PDF or DOCX files"""
    if file.filename.endswith('.pdf'):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            file.save(tmp.name)
            reader = PdfReader(tmp.name)
            text = " ".join([page.extract_text() for page in reader.pages])
            os.unlink(tmp.name)
        return text
    
    elif file.filename.endswith('.docx'):
        doc = Document(file)
        return "\n".join([para.text for para in doc.paragraphs])
    
    return ""

def preprocess(text):
    """Clean and normalize text for analysis"""
    # Remove special characters, URLs and extra spaces
    text = re.sub(r'http\S+|www\S+|https\S+', '', text, flags=re.MULTILINE)
    text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip().lower()
    
    # Lemmatization and stopword removal
    doc = nlp(text)
    tokens = [token.lemma_ for token in doc if not token.is_stop and not token.is_punct]
    return " ".join(tokens)

def calculate_similarity(resume, jd):
    """Calculate ATS score using TF-IDF and cosine similarity"""
    vectorizer = TfidfVectorizer()
    vectors = vectorizer.fit_transform([resume, jd])
    return cosine_similarity(vectors[0], vectors[1])[0][0] * 100

def get_keyword_analysis(resume, jd):
    """Identify missing and matching keywords"""
    jd_keywords = set([token.lemma_ for token in nlp(jd) 
                      if not token.is_stop and token.is_alpha])
    
    resume_keywords = set([token.lemma_ for token in nlp(resume) 
                         if not token.is_stop and token.is_alpha])
    
    missing = jd_keywords - resume_keywords
    matching = jd_keywords & resume_keywords
    
    return list(missing), list(matching)

def get_synonyms(keyword):
    """Get synonyms for keyword expansion"""
    synonyms = set()
    for syn in wordnet.synsets(keyword):
        for lemma in syn.lemmas():
            synonyms.add(lemma.name().replace('_', ' '))
    return list(synonyms)[:3]  # Return top 3 synonyms

def generate_suggestions(missing_keywords, resume_text):
    """Generate actionable optimization suggestions"""
    suggestions = []
    required_sections = ['skills', 'experience', 'education', 'projects']
    
    # Section presence check
    resume_lower = resume_text.lower()
    for section in required_sections:
        if section not in resume_lower:
            suggestions.append(f"Add a dedicated '{section.capitalize()}' section")
    
    # Keyword suggestions
    for keyword in missing_keywords[:10]:  # Limit to top 10 missing
        synonyms = get_synonyms(keyword)
        syn_text = f" (try: {', '.join(synonyms)})" if synonyms else ""
        suggestions.append(f"Incorporate '{keyword}'{syn_text}")
    
    # Formatting suggestions
    if len(resume_text) > 800:
        suggestions.append("Reduce length - aim for 1 page (600-800 words)")
    
    # Quantifiable achievements check
    if not re.search(r'\d+[%\$]|\d+\+', resume_text):
        suggestions.append("Add quantifiable achievements (e.g., 'increased sales by 20%')")
    
    return suggestions

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    resume_file = request.files.get('resume')
    job_description = request.form.get('job_description', '')
    
    if not resume_file or not job_description:
        return jsonify({"error": "Resume and job description required"}), 400
    
    # Process files
    raw_resume = extract_text(resume_file)
    if not raw_resume:
        return jsonify({"error": "Unsupported file format"}), 400
    
    # Preprocess texts
    clean_resume = preprocess(raw_resume)
    clean_jd = preprocess(job_description)
    
    # Calculate score
    score = round(calculate_similarity(clean_resume, clean_jd), 1)
    
    # Generate suggestions if needed
    result = {"score": score, "raw_resume": raw_resume}
    if score < 80:
        missing_keywords, matching_keywords = get_keyword_analysis(clean_resume, clean_jd)
        suggestions = generate_suggestions(missing_keywords, raw_resume)
        result.update({
            "suggestions": suggestions,
            "missing_keywords": missing_keywords[:20],  # Top 20 missing
            "matching_keywords": matching_keywords[:20] # Top 20 matching
        })
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)