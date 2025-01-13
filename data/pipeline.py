import spacy
from nltk.corpus import stopwords
from unidecode import unidecode
import nltk
import re
from unidecode import unidecode

# Baixar stopwords para português, se necessário
nltk.download("stopwords", quiet=True)


class TextPipeline:
    """
    Classe responsável pelo pré-processamento de textos.
    Realiza remoção de acentos, tokenização, lematização e remoção de stopwords.
    """

    def __init__(self, language_model="pt_core_news_md", stopwords_language="portuguese"):
        """
        Inicializa o pipeline carregando o modelo spaCy e a lista de stopwords.

        Args:
            language_model (str): Modelo spaCy a ser usado.
            stopwords_language (str): Idioma das stopwords a serem carregadas.
        """
        self.nlp = spacy.load(language_model)
        self.stop_words = set(stopwords.words(stopwords_language))

    def preprocess(self, text):
        """
        Executa o pré-processamento do texto.

        Args:
            text (str): Texto a ser pré-processado.

        Returns:
            str: Texto limpo, lematizado e sem stopwords.
        """
        if not text:
            return ""

        text = unidecode(text.lower())  # Normaliza e remove acentos
        text = re.sub(r'[^a-zA-Z0-9\s]', '', text)

        return text.lower()

