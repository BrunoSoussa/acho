from flask import Flask, request, jsonify, render_template, redirect, url_for
from transformers import BertForSequenceClassification, BertTokenizer
import torch
from data.pipeline import TextPipeline
import google.generativeai as genai
import json
import os
import sqlite3
from dotenv import load_dotenv
from flask import send_file
from functools import wraps
import jwt
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import random
import csv
import io
from datetime import datetime

load_dotenv()
# Garante que o processo use o diretório do arquivo como cwd, mantendo caminhos relativos consistentes
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    os.chdir(PROJECT_DIR)
except Exception:
    pass
# Garante a pasta 'sql' relativa existente
os.makedirs("sql", exist_ok=True)
GEMINI_KEY = os.getenv("GEMINI_KEY")
MODEL_NAME = os.getenv("MODEL_NAME")
HF_TOKEN = os.getenv("HF_TOKEN")  # optional: token for private HF repos
DB_PATH = os.getenv("DB_PATH", os.path.join(PROJECT_DIR, "sql", "queries_responses.db"))
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key") 


print(MODEL_NAME)
print(f"[startup] DB_PATH em uso: {DB_PATH}")


app = Flask(__name__)

# Ensure MODEL_NAME is configured and support private repos
if not MODEL_NAME or MODEL_NAME.strip().lower() == 'none':
    raise RuntimeError(
        "Missing MODEL_NAME. Set an env var MODEL_NAME with a valid HF repo id or local path to a fine-tuned sequence classification model."
    )

_auth_kwargs = {"token": HF_TOKEN} if HF_TOKEN else {}
model = BertForSequenceClassification.from_pretrained(MODEL_NAME, **_auth_kwargs)
tokenizer = BertTokenizer.from_pretrained(MODEL_NAME, **_auth_kwargs)
text_processor = TextPipeline()


id2label = model.config.id2label
with open(r"data/maping_classes.json", "r", encoding="utf-8") as f:
    mapping_classes = json.load(f)


genai.configure(api_key=GEMINI_KEY)
gemini_model = genai.GenerativeModel("gemini-1.5-flash")

def save_to_db(query, response_data, degree_of_certainty=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    category = response_data.get("document", None)
    category_id = response_data.get("id", None)

    cursor.execute("""
        INSERT INTO query_response (query, degree_of_certainty, category, category_id)
        VALUES (?, ?, ?, ?)
    """, (query, degree_of_certainty, category, category_id))

    conn.commit()
    conn.close()


def migrate_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        # Verifica colunas existentes na tabela users
        cursor.execute("PRAGMA table_info(users)")
        cols = {row[1] for row in cursor.fetchall()}
        if not cols:
            # Tabela inexistente; criação é tratada por create_tables()
            return
        # Adiciona colunas que faltarem sem dropar tabela
        if "is_admin" not in cols:
            cursor.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0")
        if "created_at" not in cols:
            cursor.execute("ALTER TABLE users ADD COLUMN created_at TEXT DEFAULT (DATETIME('now'))")
        conn.commit()
    finally:
        conn.close()


def create_tables():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Tabela de queries
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS query_response (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            degree_of_certainty REAL,
            category TEXT,
            category_id TEXT,
            created_at TEXT DEFAULT (DATETIME('now'))
        )
    """)
    
    # Tabela de usuários
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            created_at TEXT DEFAULT (DATETIME('now'))
        )
    """)
    
    # Tabela de sugestões
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS suggestions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            category TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            admin_response TEXT,
            created_at TEXT DEFAULT (DATETIME('now')),
            updated_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    # Tabela de status de correções (dia/semana)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS correction_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_type TEXT NOT NULL CHECK (key_type IN ('day','week')),
            key_value TEXT NOT NULL UNIQUE,
            completed_by INTEGER,
            completed_at TEXT DEFAULT (DATETIME('now')),
            FOREIGN KEY (completed_by) REFERENCES users (id)
        )
    """)
    
    conn.commit()
    conn.close()


def ensure_query_response_correction_columns():
    """Ensure query_response table has columns to store manual corrections.
    Columns: corrected_category, corrected_category_id, corrected_at
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA table_info(query_response)")
        cols = {row[1] for row in cursor.fetchall()}
        if "corrected_category" not in cols:
            cursor.execute("ALTER TABLE query_response ADD COLUMN corrected_category TEXT")
        if "corrected_category_id" not in cols:
            cursor.execute("ALTER TABLE query_response ADD COLUMN corrected_category_id TEXT")
        if "corrected_at" not in cols:
            cursor.execute("ALTER TABLE query_response ADD COLUMN corrected_at TEXT")
        conn.commit()
    finally:
        conn.close()

# Inicialização do banco de dados
create_tables()
migrate_database()  # Adicione esta linha para executar a migração
ensure_query_response_correction_columns()

# Criar um admin inicial se não existir
def create_initial_admin():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    admin_email = "brunosilvasousapi@gmail.com"
    admin_password = "3kpz5f5f"
    
    # Verificar se já existe um admin
    cursor.execute("SELECT * FROM users WHERE email = ?", (admin_email,))
    admin = cursor.fetchone()
    
    if admin:
        # Atualizar para ter certeza que é admin
        cursor.execute("""
            UPDATE users 
            SET is_admin = 1 
            WHERE email = ?
        """, (admin_email,))
        print(f"Admin existente atualizado: {admin_email}")
    else:
        # Criar novo admin
        hashed_password = generate_password_hash(admin_password)
        cursor.execute("""
            INSERT INTO users (email, password, is_admin)
            VALUES (?, ?, 1)
        """, (admin_email, hashed_password))
        print(f"Novo admin criado:")
        print(f"Email: {admin_email}")
        print(f"Senha: {admin_password}")
        print(f"Token necessário: {os.getenv('ADMIN_TOKEN')}")
    
    conn.commit()
    conn.close()

# Adicione esta linha após create_tables() e migrate_database()
create_initial_admin()

def verify_database_structure():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Verificar estrutura da tabela users
    cursor.execute("PRAGMA table_info(users)")
    columns = cursor.fetchall()
    print("\nEstrutura da tabela users:")
    for col in columns:
        print(f"Coluna: {col}")
    
    # Verificar dados existentes
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    print("\nUsuários existentes:")
    for user in users:
        print(f"User: {user}")
    
    conn.close()


# Adicione esta linha após create_tables() e migrate_database()
verify_database_structure()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token ausente!'}), 401
        
        try:
            token = token.split(' ')[1]  # Remove 'Bearer ' do token
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
            # Você pode adicionar verificação de usuário aqui se necessário
            
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido!'}), 401
            
        return f(*args, **kwargs)
    
    return decorated

def check_auth():
    token = request.cookies.get('token')
    if not token:
        return False
    try:
        jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True
    except:
        return False

@app.route("/")
def index():
    if not check_auth():
        return redirect(url_for('login_page'))
    return render_template("index.html")

@app.route('/login', methods=['GET'])
def login_page():
    if check_auth():
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    admin_token = request.headers.get('X-Admin-Token')
    
    print(f"Tentativa de login:")
    print(f"Email: {email}")
    print(f"Is Admin: {is_admin}")
    print(f"Admin Token: {admin_token}")
    
    if not email or not password:
        return jsonify({'message': 'Dados incompletos!'}), 400
    
    # Verificar token de admin se necessário
    if is_admin:
        if not admin_token or admin_token != os.getenv('ADMIN_TOKEN'):
            print(f"Token admin inválido. Recebido: {admin_token}")
            print(f"Token esperado: {os.getenv('ADMIN_TOKEN')}")
            return jsonify({'message': 'Token de admin inválido!'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Buscar usuário
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    
    print(f"Usuário encontrado: {user}")
    
    if user:
        is_user_admin = bool(user[3])  # Coluna is_admin
        print(f"Usuário é admin: {is_user_admin}")
        
        if is_admin and not is_user_admin:
            return jsonify({'message': 'Usuário não é administrador!'}), 401
        
        if check_password_hash(user[2], password):
            token = jwt.encode({
                'user_id': user[0],
                'email': user[1],
                'is_admin': is_user_admin,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, JWT_SECRET)
            
            response = jsonify({'token': token})
            cookie_secure = os.getenv('COOKIE_SECURE', 'false').lower() == 'true'
            # SameSite=Lax ajuda a manter o cookie em navegações dentro do mesmo site quando atrás de proxy sem HTTPS
            response.set_cookie('token', token, httponly=True, secure=cookie_secure, samesite='Lax')
            return response, 200
        else:
            print("Senha incorreta!")
    
    return jsonify({'message': 'Credenciais inválidas!'}), 401

@app.route('/logout')
def logout():
    response = redirect(url_for('login_page'))
    response.delete_cookie('token')
    return response

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    print(f"Tentativa de registro - Email: {email}")  # Debug
    
    if not email or not password:
        return jsonify({'message': 'Dados incompletos!'}), 400
    
    hashed_password = generate_password_hash(password)
    print(f"Hash gerado: {hashed_password}")  # Debug
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Verificar se o email já existe
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            print(f"Email já existe: {existing_user}")  # Debug
            return jsonify({'message': 'Email já registrado!'}), 400
        
        cursor.execute("""
            INSERT INTO users (email, password) 
            VALUES (?, ?)
        """, (email, hashed_password))
        
        # Verificar se o usuário foi criado corretamente
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        new_user = cursor.fetchone()
        print(f"Novo usuário criado: {new_user}")  # Debug
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Usuário registrado com sucesso!'}), 201
    except sqlite3.IntegrityError as e:
        print(f"Erro de integridade: {e}")  # Debug
        return jsonify({'message': 'Email já registrado!'}), 400
    except Exception as e:
        print(f"Erro inesperado: {e}")  # Debug
        return jsonify({'message': str(e)}), 500

def api_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        
        if not token:
            return jsonify({'message': 'Não autenticado!'}), 401
        
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token inválido ou expirado!'}), 401
            
        return f(*args, **kwargs)
    
    return decorated

@app.route("/search_text", methods=["POST"])
# @api_token_required
def api_search_text():
    try:
        data = request.get_json()
        query = data["query"]
        query_text = text_processor.preprocess(query)
        if len(query_text) < 3:
            return jsonify(
                    {"message": "Não encontrei uma categoria para o produto. Pode descrever melhor?"}
                ), 404
        print(query_text)

        # Tokenizar e predizer
        inputs = tokenizer(
            [query_text],
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=128,
        )
        model.eval()
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1)
            values, indices = torch.topk(probabilities, 10, dim=1)

        rounded_values = [round(value.item(), 2) for value in values[0]]
        print(rounded_values)
        top_labels = [id2label[idx.item()] for idx in indices[0]]
        print(top_labels)

        # Atualiza a extração dos dados a partir da nova estrutura de mapping_classes
        top_results = []
        for i, label in enumerate(top_labels):
            subcat_mapping = None
            # Procura pela subcategoria em cada grupo
            for group in mapping_classes.values():
                if label in group:
                    subcat_mapping = group[label]
                    break
            if subcat_mapping:
                document = list(subcat_mapping.keys())[0]
                cat_id = list(subcat_mapping.values())[0]
            else:
                document = ""
                cat_id = ""
            top_results.append({
                "document": document,
                "id": cat_id,
                "degree_of_certainty": rounded_values[i],
            })

        # Se o grau de certeza do primeiro resultado for suficientemente alto, salva e retorna
        if top_results[0]["degree_of_certainty"] >= 0.9:
            save_to_db(query, top_results[0], top_results[0]["degree_of_certainty"])
            return jsonify(top_results[0]), 200

        filtered_results = [
            {"document": item["document"], "id": item["id"]}
            for item in top_results
            if item["degree_of_certainty"] > 0
        ]
        print(f"filtered results: {filtered_results}")

        prompt = f"""
        Você é um modelo especializado em detecção de intenção de compra.
        A intenção do usuário é: "{query}".
        As categorias disponíveis são: {filtered_results}.
        Retorne o ID da categoria mais adequada em formato JSON, com uma única chave 'ID' e o valor correspondente à categoria.
        Se nenhuma categoria for apropriada, retorne "None" nuncar retorne uma categoria que não não tiver nada relacionado
        com intenção do usuário.
        Não adicione formatação ou metadados extras.
        """
        try:
            response = gemini_model.generate_content(prompt)
            response_text = response.text.strip().replace("```json", "").replace("```", "")

            if response_text == "None":
                return jsonify(
                    {"message": "Não encontrei uma categoria para o produto. Pode descrever melhor?"}
                ), 404

            try:
                category_data = json.loads(response_text)
                category_id = category_data.get("ID")
                matching_document = next(
                    (result for result in top_results if result["id"] == str(category_id)),
                    None,
                )

                if matching_document:
                    save_to_db(query, matching_document, matching_document.get("degree_of_certainty", None))
                    return jsonify(matching_document), 200
                else:
                    return jsonify(
                        {"message": "ID retornado pelo modelo não encontrado nos resultados."}
                    ), 404

            except json.JSONDecodeError:
                return jsonify({"error": "Erro ao interpretar a resposta do modelo."}), 500
        except Exception as e:
            # Em caso de erro na chamada do modelo Gemini, salva e retorna o primeiro resultado
            save_to_db(query, top_results[0], top_results[0].get("degree_of_certainty", None))
            return jsonify(top_results[0]), 202

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/search_family", methods=["POST"])
def api_search_family():
    try:
        data = request.get_json()
        query = data["query"]
        query_text = text_processor.preprocess(query)
        print("Query pré-processada:", query_text)

        # Tokenização e preparação dos inputs para o modelo
        inputs = tokenizer(
            [query_text],
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=128,
        )

        # Realiza a predição com o modelo em modo avaliação
        model.eval()
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1)
            # Obtém os 10 melhores resultados
            values, indices = torch.topk(probabilities, 10, dim=1)

        # Converte as probabilidades e índices para listas utilizáveis
        rounded_values = [round(val.item(), 2) for val in values[0]]
        top_labels = [id2label[idx.item()] for idx in indices[0]]
        print("Top labels:", top_labels)
        print("Probabilidades:", rounded_values)

        # Percorre todos os rótulos com probabilidade > 0 e busca as famílias correspondentes
        families_found = {}
        for i, label in enumerate(top_labels):
            if rounded_values[i] > 0:
                # Verifica em cada família se o label está presente
                for family, subcategories in mapping_classes.items():
                    if label in subcategories:
                        # Se a família ainda não foi adicionada, adiciona-a com todas as suas subcategorias
                        if family not in families_found:
                            families_found[family] = subcategories
                        break  # interrompe a busca para este label

        if not families_found:
            return jsonify({"message": "Nenhuma família encontrada com probabilidade > 0."}), 404

        return jsonify(families_found), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_all_texts", methods=["GET"])
def api_get_all_texts():
    try:
        output = {}
        # Itera por cada categoria e suas subcategorias
        for categoria, subcategorias in mapping_classes.items():
            subs = []
            for subcat in subcategorias.values():
                document = list(subcat.keys())[0]
                cat_id = list(subcat.values())[0]
                subs.append({"document": document, "id": cat_id})
            output[categoria] = subs
        return jsonify(output), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route("/get_queries", methods=["GET"])
#@token_required
def get_queries():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM query_response")
        rows = cursor.fetchall()
        conn.close()

        data = [
            {
                "id": row[0],
                "query": row[1],
                "degree_of_certainty": row[2],
                "category": row[3],
                "category_id": row[4],
                "created_at": row[5],
                "corrected_category": row[6] if len(row) > 6 else None,
                "corrected_category_id": row[7] if len(row) > 7 else None,
                "corrected_at": row[8] if len(row) > 8 else None,
            }
            for row in rows
        ]
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route("/download_db", methods=["GET"])
@token_required
def download_db():
    try:
        # Verifica se o banco de dados existe
        if not os.path.exists(DB_PATH):
            return jsonify({"error": "Banco de dados não encontrado."}), 404

        # Envia o arquivo do banco de dados como download
        return send_file(DB_PATH, as_attachment=True, download_name="queries_responses.db")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/suggestions', methods=['POST'])
@api_token_required
def create_suggestion():
    data = request.get_json()
    category = data.get('category')
    
    if not category:
        return jsonify({'message': 'Categoria é obrigatória!'}), 400
        
    token = request.cookies.get('token')
    user_data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    user_id = user_data['user_id']
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO suggestions (user_id, category)
        VALUES (?, ?)
    """, (user_id, category))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Sugestão enviada com sucesso!'}), 201

@app.route('/api/suggestions', methods=['GET'])
@api_token_required
def get_suggestions():
    token = request.cookies.get('token')
    user_data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    user_id = user_data['user_id']
    is_admin = user_data.get('is_admin', False)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if is_admin:
        # Admins veem todas as sugestões pendentes e suas próprias
        cursor.execute("""
            SELECT s.*, u.email 
            FROM suggestions s
            JOIN users u ON s.user_id = u.id
            WHERE s.status = 'pending' OR s.user_id = ?
            ORDER BY 
                CASE 
                    WHEN s.status = 'pending' THEN 1 
                    ELSE 2 
                END,
                s.created_at DESC
        """, (user_id,))
    else:
        # Usuários normais veem apenas suas próprias sugestões
        cursor.execute("""
            SELECT s.*, NULL as email
            FROM suggestions s
            WHERE s.user_id = ?
            ORDER BY s.created_at DESC
        """, (user_id,))
    
    suggestions = cursor.fetchall()
    conn.close()
    
    return jsonify([{
        'id': s[0],
        'user_id': s[1],
        'category': s[2],
        'status': s[3],
        'admin_response': s[4],
        'created_at': s[5],
        'updated_at': s[6],
        'user_email': s[7]
    } for s in suggestions]), 200

@app.route('/api/suggestions/<int:suggestion_id>', methods=['PUT'])
@api_token_required
def update_suggestion(suggestion_id):
    token = request.cookies.get('token')
    user_data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    if not user_data.get('is_admin', False):
        return jsonify({'message': 'Acesso não autorizado!'}), 403
    
    data = request.get_json()
    status = data.get('status')
    admin_response = data.get('admin_response')
    
    if not status or not admin_response:
        return jsonify({'message': 'Status e resposta são obrigatórios!'}), 400
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE suggestions 
        SET status = ?, admin_response = ?, updated_at = DATETIME('now')
        WHERE id = ?
    """, (status, admin_response, suggestion_id))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Sugestão atualizada com sucesso!'}), 200

@app.route('/create-admin', methods=['POST'])
def create_admin():
    if request.headers.get('X-Admin-Key') != 'sua_chave_secreta':
        print(request.headers.get('X-Admin-Key'))
        return jsonify({'message': 'Não autorizado'}), 403
        
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Dados incompletos'}), 400
        
    hashed_password = generate_password_hash(password)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (email, password, is_admin)
        VALUES (?, ?, 1)
    """, (email, hashed_password))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Admin criado com sucesso'}), 201

@app.route('/api/statistics', methods=['GET'])
@api_token_required
def get_statistics():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Buscar top categorias mais pesquisadas
    cursor.execute("""
        SELECT category, COUNT(*) as count 
        FROM query_response 
        WHERE category IS NOT NULL 
        GROUP BY category 
        ORDER BY count DESC 
        LIMIT 10
    """)
    top_categories = cursor.fetchall()
    
    # Buscar total de pesquisas
    cursor.execute("SELECT COUNT(*) FROM query_response")
    total_searches = cursor.fetchone()[0]
    
    # Buscar média de certeza
    cursor.execute("""
        SELECT AVG(degree_of_certainty) 
        FROM query_response 
        WHERE degree_of_certainty IS NOT NULL
    """)
    avg_certainty = cursor.fetchone()[0]
    
    # Buscar pesquisas recentes
    cursor.execute("""
        SELECT query, category, degree_of_certainty, created_at
        FROM query_response
        ORDER BY created_at DESC
        LIMIT 5
    """)
    recent_searches = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        'top_categories': [{'category': cat, 'count': count} for cat, count in top_categories],
        'total_searches': total_searches,
        'average_certainty': round(avg_certainty, 2) if avg_certainty else 0,
        'recent_searches': [{
            'query': search[0],
            'category': search[1],
            'certainty': search[2],
            'created_at': search[3]
        } for search in recent_searches]
    }), 200

@app.route('/api/examples', methods=['GET'])
@api_token_required
def get_random_examples():
    # Caminho completo do arquivo
    file_path = r"analises/dataset_transformado_not_lema.csv"
    examples_by_category = {}
    
    try:
        # Verificar se o arquivo existe
        if not os.path.exists(file_path):
            print(f"Arquivo não encontrado: {file_path}")
            return jsonify({"error": "Arquivo de exemplos não encontrado"}), 404
            
        print(f"Lendo arquivo: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as file:
            # Pular o cabeçalho
            header = next(file)
            print(f"Cabeçalho: {header.strip()}")
            
            # Processar cada linha
            line_count = 0
            for line in file:
                line_count += 1
                if line.strip():
                    try:
                        # Dividir a linha usando vírgula
                        texto, label = line.strip().split(',')
                        
                        # Remover aspas se existirem
                        texto = texto.strip('"').strip()
                        label = label.strip('"').strip()
                        
                        if not label or not texto:
                            print(f"Linha {line_count} com dados vazios: {line.strip()}")
                            continue
                        
                        if label not in examples_by_category:
                            examples_by_category[label] = []
                        examples_by_category[label].append(texto)
                        
                    except Exception as e:
                        print(f"Erro ao processar linha {line_count}: {line.strip()}")
                        print(f"Erro: {str(e)}")
                        continue
        
        # Debug: imprimir quantidade de exemplos por categoria
        print("\nQuantidade de exemplos por categoria:")
        for label, examples in examples_by_category.items():
            print(f"{label}: {len(examples)} exemplos")
        
        if not examples_by_category:
            print("Nenhum exemplo foi carregado")
            return jsonify({"error": "Nenhum exemplo foi carregado"}), 500
        
        # Selecionar 5 exemplos aleatórios de cada categoria
        random_examples = {}
        for label, texts in examples_by_category.items():
            if texts:  # Verificar se há exemplos na categoria
                sample_size = min(5, len(texts))
                random_examples[label] = random.sample(texts, sample_size)
        
        # Debug: verificar resultado final
        print("\nCategorias no resultado final:", len(random_examples))
        print("Primeiras categorias:", list(random_examples.keys())[:3])
        
        return jsonify(random_examples), 200
        
    except Exception as e:
        print(f"Erro ao processar arquivo: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Erro ao processar exemplos: {str(e)}"}), 500

@app.route('/api/database/<table_name>', methods=['GET'])
@token_required
def get_table_data(table_name):
    # Validar nome da tabela para evitar SQL injection
    allowed_tables = {'query_response', 'users', 'suggestions'}
    if table_name not in allowed_tables:
        return jsonify({'error': 'Tabela não permitida'}), 403
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Obter nomes das colunas
        cursor.execute(f'PRAGMA table_info({table_name})')
        columns = [column[1] for column in cursor.fetchall()]
        
        # Obter dados
        cursor.execute(f'SELECT * FROM {table_name} ORDER BY created_at DESC LIMIT 1000')
        rows = cursor.fetchall()
        
        # Converter para dicionários
        row_dicts = []
        for row in rows:
            row_dict = {}
            for i, value in enumerate(row):
                # Converter datetime para string se necessário
                if isinstance(value, datetime):
                    value = value.isoformat()
                row_dict[columns[i]] = value
            row_dicts.append(row_dict)
        
        return jsonify({
            'columns': columns,
            'rows': row_dicts
        })
        
    except Exception as e:
        print(f"Erro ao buscar dados da tabela {table_name}:", e)
        return jsonify({'error': 'Erro ao buscar dados'}), 500
    
    finally:
        if 'conn' in locals():
            conn.close()

# Adicione uma rota para listar as tabelas disponíveis
@app.route('/api/database/tables', methods=['GET'])
@token_required
def get_available_tables():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Obter lista de tabelas
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        return jsonify({
            'tables': [table for table in tables if table not in ['sqlite_sequence']]
        })
        
    except Exception as e:
        print("Erro ao listar tabelas:", e)
        return jsonify({'error': 'Erro ao listar tabelas'}), 500
    
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/searches', methods=['GET'])
@api_token_required
def list_searches():
    """Paginated list of searches with optional week filter (year-week)."""
    try:
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        year_week = request.args.get('year_week')  # format YYYY-WW
        day_date = request.args.get('date')  # format YYYY-MM-DD

        # Validate date if provided
        if day_date:
            try:
                datetime.strptime(day_date, '%Y-%m-%d')
            except ValueError:
                return jsonify({'error': 'Parâmetro date inválido. Use YYYY-MM-DD.'}), 400

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        base_query = "SELECT id, query, degree_of_certainty, category, category_id, created_at, IFNULL(corrected_category, ''), IFNULL(corrected_category_id, ''), corrected_at FROM query_response"
        params = []
        if day_date:
            base_query += " WHERE DATE(created_at) = ?"
            params.append(day_date)
        elif year_week:
            base_query += " WHERE strftime('%Y-%W', created_at) = ?"
            params.append(year_week)
        base_query += " ORDER BY datetime(created_at) DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(base_query, params)
        rows = cursor.fetchall()

        # total count
        if day_date:
            cursor.execute("SELECT COUNT(*) FROM query_response WHERE DATE(created_at) = ?", (day_date,))
        elif year_week:
            cursor.execute("SELECT COUNT(*) FROM query_response WHERE strftime('%Y-%W', created_at) = ?", (year_week,))
        else:
            cursor.execute("SELECT COUNT(*) FROM query_response")
        total = cursor.fetchone()[0]

        conn.close()

        data = [
            {
                'id': r[0],
                'query': r[1],
                'degree_of_certainty': r[2],
                'category': r[3],
                'category_id': r[4],
                'created_at': r[5],
                'corrected_category': r[6] or None,
                'corrected_category_id': r[7] or None,
                'corrected_at': r[8],
            }
            for r in rows
        ]
        return jsonify({'total': total, 'items': data}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/searches/weekly', methods=['GET'])
@api_token_required
def searches_weekly():
    """Return weekly aggregation in format: [{'year_week': '2025-35', 'count': 10}]"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT strftime('%Y-%W', created_at) as year_week, COUNT(*) as count
            FROM query_response
            GROUP BY year_week
            ORDER BY year_week DESC
            """
        )
        rows = cursor.fetchall()
        conn.close()
        return jsonify([{'year_week': rw[0], 'count': rw[1]} for rw in rows]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/searches/<int:search_id>/category', methods=['PUT'])
@api_token_required
def correct_search_category(search_id):
    """Admin-only: correct the category/category_id assigned by AI."""
    try:
        token = request.cookies.get('token')
        user_data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if not user_data.get('is_admin', False):
            return jsonify({'message': 'Acesso não autorizado!'}), 403

        body = request.get_json() or {}
        corrected_category = body.get('corrected_category')
        corrected_category_id = body.get('corrected_category_id')
        if not corrected_category or not corrected_category_id:
            return jsonify({'message': 'Campos corrected_category e corrected_category_id são obrigatórios'}), 400

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE query_response
            SET corrected_category = ?, corrected_category_id = ?, corrected_at = DATETIME('now')
            WHERE id = ?
            """,
            (corrected_category, corrected_category_id, search_id),
        )
        conn.commit()
        conn.close()
        return jsonify({'message': 'Categoria corrigida com sucesso!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-auth', methods=['GET'])
@api_token_required
def api_check_auth():
    try:
        token = request.cookies.get('token')
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return jsonify({
            'authenticated': True,
            'email': data.get('email'),
            'is_admin': bool(data.get('is_admin', False))
        }), 200
    except Exception:
        return jsonify({'authenticated': False}), 401

@app.route('/api/searches/export', methods=['GET'])
@api_token_required
def export_searches_csv():
    """Exporta buscas em CSV. Filtro opcional por semana (year_week = YYYY-WW)."""
    try:
        year_week = request.args.get('year_week')
        day_date = request.args.get('date')  # format YYYY-MM-DD

        if day_date:
            try:
                datetime.strptime(day_date, '%Y-%m-%d')
            except ValueError:
                return jsonify({'error': 'Parâmetro date inválido. Use YYYY-MM-DD.'}), 400

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        query = (
            "SELECT id, query, degree_of_certainty, category, category_id, created_at, "
            "IFNULL(corrected_category, ''), IFNULL(corrected_category_id, ''), IFNULL(corrected_at, ''), "
            "strftime('%Y-%W', created_at) as year_week "
            "FROM query_response"
        )
        params = []
        if day_date:
            query += " WHERE DATE(created_at) = ?"
            params.append(day_date)
        elif year_week:
            query += " WHERE strftime('%Y-%W', created_at) = ?"
            params.append(year_week)
        query += " ORDER BY datetime(created_at) DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'id','query','degree_of_certainty','category','category_id','created_at',
            'corrected_category','corrected_category_id','corrected_at','year_week'
        ])
        for r in rows:
            writer.writerow(list(r))

        csv_bytes = io.BytesIO(output.getvalue().encode('utf-8-sig'))
        filename = f"searches_{day_date if day_date else (year_week if year_week else 'all')}.csv"
        return send_file(csv_bytes, as_attachment=True, download_name=filename, mimetype='text/csv')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== Correções: marcar dia/semana como concluído =====
def _require_admin():
    token = request.cookies.get('token')
    if not token:
        return False, None
    try:
        user_data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = user_data.get('user_id')
        if not user_id:
            return False, None
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        return (bool(row and row[0]), user_id)
    except Exception:
        return False, None

@app.route('/api/searches/corrections/status', methods=['GET'])
@api_token_required
def get_corrections_status():
    """Retorna status de conclusão para um dia e/ou semana.
    Query params: date=YYYY-MM-DD, year_week=YYYY-WW
    Response: { day: true/false/null, week: true/false/null }
    """
    try:
        day_date = request.args.get('date')
        year_week = request.args.get('year_week')
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        result = {'day': None, 'week': None}
        if day_date:
            cursor.execute("SELECT 1 FROM correction_status WHERE key_type='day' AND key_value=?", (day_date,))
            result['day'] = cursor.fetchone() is not None
        if year_week:
            cursor.execute("SELECT 1 FROM correction_status WHERE key_type='week' AND key_value=?", (year_week,))
            result['week'] = cursor.fetchone() is not None
        conn.close()
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/searches/corrections/complete', methods=['POST'])
@api_token_required
def complete_corrections():
    """Marca um dia ou semana como concluído.
    Body JSON: { "type": "day|week", "key": "YYYY-MM-DD|YYYY-WW" }
    Admin only.
    """
    is_admin, user_id = _require_admin()
    if not is_admin:
        return jsonify({'error': 'Apenas administradores podem concluir correções.'}), 403
    try:
        data = request.get_json(force=True)
        key_type = data.get('type')
        key_value = data.get('key')
        if key_type not in ('day','week') or not key_value:
            return jsonify({'error': 'Parâmetros inválidos'}), 400
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO correction_status (id, key_type, key_value, completed_by, completed_at)\n             SELECT id, ?, ?, ?, DATETIME('now') FROM (SELECT id FROM correction_status WHERE key_value = ?)\n            ",
            (key_type, key_value, user_id, key_value)
        )
        # Se não existia, faz INSERT normal
        if cursor.rowcount == 0:
            cursor.execute(
                "INSERT INTO correction_status (key_type, key_value, completed_by) VALUES (?, ?, ?)",
                (key_type, key_value, user_id)
            )
        conn.commit()
        conn.close()
        return jsonify({'message': 'Marcado como concluído'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/searches/corrections/uncomplete', methods=['POST'])
@api_token_required
def uncomplete_corrections():
    """Desmarca um dia ou semana como concluído.
    Body JSON: { "type": "day|week", "key": "YYYY-MM-DD|YYYY-WW" }
    Admin only.
    """
    is_admin, _ = _require_admin()
    if not is_admin:
        return jsonify({'error': 'Apenas administradores podem concluir correções.'}), 403
    try:
        data = request.get_json(force=True)
        key_type = data.get('type')
        key_value = data.get('key')
        if key_type not in ('day','week') or not key_value:
            return jsonify({'error': 'Parâmetros inválidos'}), 400
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM correction_status WHERE key_type=? AND key_value=?", (key_type, key_value))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Marcado como não concluído'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/searches/daily', methods=['GET'])
@api_token_required
def searches_daily():
    """Retorna agregação diária em formato: [{'day': '2025-08-30', 'count': 12}].
    Filtro opcional por semana (year_week = YYYY-WW).
    """
    try:
        year_week = request.args.get('year_week')
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = (
            "SELECT DATE(created_at) as day, COUNT(*) as count "
            "FROM query_response "
        )
        params = []
        if year_week:
            query += "WHERE strftime('%Y-%W', created_at) = ? "
            params.append(year_week)
        query += "GROUP BY day ORDER BY day DESC"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return jsonify([{'day': r[0], 'count': r[1]} for r in rows]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/searches/corrections/list', methods=['GET'])
@api_token_required
def list_corrections_keys():
    """Lista chaves concluídas de correções por tipo.
    Query params: type=day|week
    Response: { keys: ["YYYY-MM-DD" | "YYYY-WW", ...] }
    """
    try:
        key_type = request.args.get('type')
        if key_type not in ('day', 'week'):
            return jsonify({'error': 'Parâmetro type inválido. Use day ou week.'}), 400
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT key_value FROM correction_status WHERE key_type = ? ORDER BY key_value DESC", (key_type,))
        keys = [r[0] for r in cursor.fetchall()]
        conn.close()
        return jsonify({'keys': keys}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
