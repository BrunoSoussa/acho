from flask import Flask, request, jsonify, render_template, redirect, url_for
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
import threading

load_dotenv()
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    os.chdir(PROJECT_DIR)
except Exception:
    pass
os.makedirs("sql", exist_ok=True)
GEMINI_KEY = os.getenv("GEMINI_KEY")
DB_PATH = os.getenv("DB_PATH", os.path.join(PROJECT_DIR, "sql", "queries_responses.db"))
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key") 


print(f"[startup] DB_PATH em uso: {DB_PATH}")


app = Flask(__name__)

text_processor = TextPipeline()

MAPPING_PATH = r"data/maping_classes.json"
MAPPING_LOCK = threading.Lock()
with open(MAPPING_PATH, "r", encoding="utf-8") as f:
    mapping_classes = json.load(f)


genai.configure(api_key=GEMINI_KEY)
GEMINI_MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
gemini_model = genai.GenerativeModel(GEMINI_MODEL_NAME)

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
        cursor.execute("PRAGMA table_info(users)")
        cols = {row[1] for row in cursor.fetchall()}
        if not cols:
            return
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
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            created_at TEXT DEFAULT (DATETIME('now'))
        )
    """)
    
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

create_tables()
migrate_database()  
ensure_query_response_correction_columns()

def create_initial_admin():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    admin_email = "brunosilvasousapi@gmail.com"
    admin_password = "3kpz5f5f"
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (admin_email,))
    admin = cursor.fetchone()
    
    if admin:
        cursor.execute("""
            UPDATE users 
            SET is_admin = 1 
            WHERE email = ?
        """, (admin_email,))
        print(f"Admin existente atualizado: {admin_email}")
    else:
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

create_initial_admin()

def verify_database_structure():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("PRAGMA table_info(users)")
    columns = cursor.fetchall()
    print("\nEstrutura da tabela users:")
    for col in columns:
        print(f"Coluna: {col}")
    
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    print("\nUsuários existentes:")
    for user in users:
        print(f"User: {user}")
    
    conn.close()

verify_database_structure()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token ausente!'}), 401
        
        try:
            token = token.split(' ')[1]  
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
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
    
    if is_admin:
        if not admin_token or admin_token != os.getenv('ADMIN_TOKEN'):
            print(f"Token admin inválido. Recebido: {admin_token}")
            print(f"Token esperado: {os.getenv('ADMIN_TOKEN')}")
            return jsonify({'message': 'Token de admin inválido!'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    
    print(f"Usuário encontrado: {user}")
    
    if user:
        is_user_admin = bool(user[3])  
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
    
    print(f"Tentativa de registro - Email: {email}")  
    
    if not email or not password:
        return jsonify({'message': 'Dados incompletos!'}), 400
    
    hashed_password = generate_password_hash(password)
    print(f"Hash gerado: {hashed_password}")  
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            print(f"Email já existe: {existing_user}")  
            return jsonify({'message': 'Email já registrado!'}), 400
        
        cursor.execute("""
            INSERT INTO users (email, password) 
            VALUES (?, ?)
        """, (email, hashed_password))
        
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        new_user = cursor.fetchone()
        print(f"Novo usuário criado: {new_user}")  
    
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Usuário registrado com sucesso!'}), 201
    except sqlite3.IntegrityError as e:
        print(f"Erro de integridade: {e}")  
        return jsonify({'message': 'Email já registrado!'}), 400
    except Exception as e:
        print(f"Erro inesperado: {e}")  
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
        query = data.get("query", "")
        query_text = text_processor.preprocess(query)
        if len(query_text) < 3:
            return jsonify(
                {"message": "Não encontrei uma categoria para o produto. Pode descrever melhor?"}
            ), 404

        options = []
        for group in mapping_classes.values():
            for subcat in group.values():
                document = list(subcat.keys())[0]
                cat_id = str(list(subcat.values())[0])
                options.append({"document": document, "id": cat_id})

        if not options:
            return jsonify({"error": "Catálogo de categorias vazio."}), 500

        system_instruction = (
            "Você é um classificador de intenção de compra. Dado um texto do usuário e uma lista de opções de categorias, "
            "selecione a opção mais adequada. Responda SOMENTE com JSON estrito."
        )
        prompt = f"""
        Texto do usuário: "{query}"
        Opções (lista de objetos com document e id): {json.dumps(options, ensure_ascii=False)}

        Regras:
        - Retorne estritamente um JSON no formato: {{"document": string, "id": string, "degree_of_certainty": number entre 0 e 1}}
        - Se nenhuma opção for apropriada, retorne: {{"None": true}}
        - Não adicione comentários, blocos markdown, ou chaves extras.
        - O campo id deve ser exatamente um dos ids presentes nas opções.
        - O campo document deve corresponder exatamente ao document da opção escolhida.
        """
        try:
            response = gemini_model.generate_content(prompt)
            response_text = response.text.strip()
            cleaned = response_text.replace("```json", "").replace("```", "").strip()

            try:
                result = json.loads(cleaned)
            except json.JSONDecodeError:
                return jsonify({"error": "Erro ao interpretar a resposta do Gemini."}), 502

            if isinstance(result, dict) and result.get("None") is True:
                return jsonify(
                    {"message": "Não encontrei uma categoria para o produto. Pode descrever melhor?"}
                ), 404

            if not all(k in result for k in ["document", "id", "degree_of_certainty"]):
                return jsonify({"error": "Resposta do Gemini incompleta."}), 502

            picked = next((o for o in options if o["id"] == str(result["id"]) and o["document"] == result["document"]), None)
            if not picked:
                return jsonify({"error": "ID/document retornado não corresponde às opções."}), 404

            try:
                certainty = float(result["degree_of_certainty"])
                certainty = max(0.0, min(1.0, certainty))
            except Exception:
                certainty = None

            payload = {
                "document": picked["document"],
                "id": picked["id"],
                "degree_of_certainty": certainty,
            }

            save_to_db(query, payload, certainty)
            return jsonify(payload), 200
        except Exception as e:
            return jsonify({"error": f"Falha ao consultar o Gemini: {str(e)}"}), 502

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/search_family", methods=["POST"])
def api_search_family():
    try:
        data = request.get_json()
        query = data.get("query", "")
        query_text = text_processor.preprocess(query)
        if len(query_text) < 3:
            return jsonify({"message": "Descreva melhor sua busca."}), 400

        families = {}
        for family, subcategories in mapping_classes.items():
            families[family] = list(subcategories.keys())

        system_instruction = (
            "Dada uma consulta do usuário e famílias com suas subcategorias (nomes), "
            "selecione as famílias mais relevantes. Responda SOMENTE com JSON."
        )
        prompt = f"""
        Texto do usuário: "{query}"
        Famílias disponíveis (mapa família -> lista de subcategorias): {json.dumps(families, ensure_ascii=False)}

        Regras:
        - Retorne estritamente um JSON no formato: {{"families": [string]}} com até 5 famílias mais relevantes.
        - Se nenhuma família for apropriada, retorne: {{"families": []}}.
        - Não adicione comentários, blocos markdown, nem chaves extras.
        """
        try:
            response = gemini_model.generate_content(prompt)
            response_text = response.text.strip()
            cleaned = response_text.replace("```json", "").replace("```", "").strip()

            try:
                result = json.loads(cleaned)
            except json.JSONDecodeError:
                return jsonify({"error": "Erro ao interpretar a resposta do Gemini."}), 502

            fam_list = result.get("families", []) if isinstance(result, dict) else []
            if not isinstance(fam_list, list):
                fam_list = []

            fam_list = [f for f in fam_list if f in mapping_classes]
            if not fam_list:
                return jsonify({"message": "Nenhuma família encontrada com a consulta."}), 404

            families_found = {}
            for f in fam_list:
                families_found[f] = mapping_classes[f]

            return jsonify(families_found), 200
        except Exception as e:
            return jsonify({"error": f"Falha ao consultar o Gemini: {str(e)}"}), 502

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_all_texts", methods=["GET"])
def api_get_all_texts():
    try:
        output = {}
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
        if not os.path.exists(DB_PATH):
            return jsonify({"error": "Banco de dados não encontrado."}), 404

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
    
    cursor.execute("""
        SELECT category, COUNT(*) as count 
        FROM query_response 
        WHERE category IS NOT NULL 
        GROUP BY category 
        ORDER BY count DESC 
        LIMIT 10
    """)
    top_categories = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM query_response")
    total_searches = cursor.fetchone()[0]
    
    cursor.execute("""
        SELECT AVG(degree_of_certainty) 
        FROM query_response 
        WHERE degree_of_certainty IS NOT NULL
    """)
    avg_certainty = cursor.fetchone()[0]
    
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
    file_path = r"analises/dataset_transformado_not_lema.csv"
    examples_by_category = {}
    
    try:
        if not os.path.exists(file_path):
            print(f"Arquivo não encontrado: {file_path}")
            return jsonify({"error": "Arquivo de exemplos não encontrado"}), 404
            
        print(f"Lendo arquivo: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as file:
            header = next(file)
            print(f"Cabeçalho: {header.strip()}")
            
            line_count = 0
            for line in file:
                line_count += 1
                if line.strip():
                    try:
                        texto, label = line.strip().split(',')
                        
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
        
        print("\nQuantidade de exemplos por categoria:")
        for label, examples in examples_by_category.items():
            print(f"{label}: {len(examples)} exemplos")
        
        if not examples_by_category:
            print("Nenhum exemplo foi carregado")
            return jsonify({"error": "Nenhum exemplo foi carregado"}), 500
        
        random_examples = {}
        for label, texts in examples_by_category.items():
            if texts:  
                sample_size = min(5, len(texts))
                random_examples[label] = random.sample(texts, sample_size)
        
        print("\nCategorias no resultado final:", len(random_examples))
        print("Primeiras categorias:", list(random_examples.keys())[:3])
        
        return jsonify(random_examples), 200
        
    except Exception as e:
        print(f"Erro ao processar arquivo: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Erro ao processar exemplos: {str(e)}"}), 500

@app.route("/api/database/<table_name>", methods=["GET"])
@token_required
def get_table_data(table_name):
    allowed_tables = {'query_response', 'users', 'suggestions'}
    if table_name not in allowed_tables:
        return jsonify({'error': 'Tabela não permitida'}), 403
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(f'PRAGMA table_info({table_name})')
        columns = [column[1] for column in cursor.fetchall()]
        
        cursor.execute(f'SELECT * FROM {table_name} ORDER BY created_at DESC LIMIT 1000')
        rows = cursor.fetchall()
        
        row_dicts = []
        for row in rows:
            row_dict = {}
            for i, value in enumerate(row):
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

@app.route("/api/database/tables", methods=["GET"])
@token_required
def get_available_tables():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
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
    try:
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        year_week = request.args.get('year_week')  
        day_date = request.args.get('date')  

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
    try:
        year_week = request.args.get('year_week')
        day_date = request.args.get('date')  

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

# ===== Helpers para gerenciamento de categorias =====
def load_mapping():
    with open(MAPPING_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_mapping(mapping):
    # Persistência com lock para evitar condições de corrida
    with MAPPING_LOCK:
        with open(MAPPING_PATH, 'w', encoding='utf-8') as f:
            json.dump(mapping, f, ensure_ascii=False, indent=2)
    # Atualiza cache em memória
    global mapping_classes
    mapping_classes = mapping

def find_category_by_id(mapping, cat_id):
    cat_id = str(cat_id)
    for family, subcats in mapping.items():
        for label, doc_map in subcats.items():
            document = list(doc_map.keys())[0]
            value_id = str(list(doc_map.values())[0])
            if value_id == cat_id:
                return {
                    'family': family,
                    'label': label,
                    'document': document,
                    'id': value_id,
                }
    return None

def flatten_categories(mapping):
    items = []
    for family, subcats in mapping.items():
        for label, doc_map in subcats.items():
            document = list(doc_map.keys())[0]
            value_id = str(list(doc_map.values())[0])
            items.append({
                'family': family,
                'label': label,
                'document': document,
                'id': value_id,
            })
    return items

def get_next_category_id(mapping):
    max_id = 0
    for family, subcats in mapping.items():
        for label, doc_map in subcats.items():
            try:
                value_id = list(doc_map.values())[0]
                max_id = max(max_id, int(value_id))
            except Exception:
                # Ignora ids não numéricos
                continue
    return str(max_id + 1)

# ===== Rotas de Categorias (CRUD) =====
@app.route('/api/categories', methods=['GET'])
@api_token_required
def list_categories():
    try:
        mapping = load_mapping()
        return jsonify(flatten_categories(mapping)), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/categories', methods=['POST'])
@api_token_required
def create_category():
    # Somente admin
    is_admin, _ = _require_admin()
    if not is_admin:
        return jsonify({'error': 'Apenas administradores podem criar categorias.'}), 403

    try:
        data = request.get_json() or {}
        family = data.get('family')
        label = data.get('label')
        document = data.get('document')
        # id é gerado automaticamente
        if not all([family, label, document]):
            return jsonify({'error': 'Campos obrigatórios: family, label, document.'}), 400

        mapping = load_mapping()

        # Gerar próximo id (max+1)
        cat_id = get_next_category_id(mapping)

        # Cria família se não existir
        if family not in mapping:
            mapping[family] = {}

        # Verifica label duplicado na família
        if label in mapping[family]:
            return jsonify({'error': 'Já existe uma subcategoria com este label nesta família.'}), 409

        # Insere
        mapping[family][label] = {document: str(cat_id)}
        save_mapping(mapping)
        return jsonify({'message': 'Categoria criada com sucesso.', 'id': str(cat_id)}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/categories/<cat_id>', methods=['PUT'])
@api_token_required
def update_category(cat_id):
    # Somente admin
    is_admin, _ = _require_admin()
    if not is_admin:
        return jsonify({'error': 'Apenas administradores podem editar categorias.'}), 403

    try:
        data = request.get_json() or {}
        new_family = data.get('family')  # opcional: mover para outra família
        new_label = data.get('label')    # opcional: renomear label
        new_document = data.get('document')  # opcional
        new_id = data.get('id')  # opcional: alterar id (mantendo unicidade)

        mapping = load_mapping()
        current = find_category_by_id(mapping, cat_id)
        if not current:
            return jsonify({'error': 'Categoria não encontrada.'}), 404

        cur_family = current['family']
        cur_label = current['label']
        cur_document = current['document']
        cur_id = current['id']

        target_family = new_family if new_family else cur_family

        # Se mudar ID, verificar unicidade
        if new_id and str(new_id) != str(cur_id):
            if find_category_by_id(mapping, new_id):
                return jsonify({'error': 'Já existe uma categoria com o novo id informado.'}), 409

        # Se mover de família, criar destino se não existir
        if target_family not in mapping:
            mapping[target_family] = {}

        # Remover do local atual
        try:
            del mapping[cur_family][cur_label]
            if not mapping[cur_family]:
                # remove família vazia
                del mapping[cur_family]
        except KeyError:
            pass

        # Novo label/document/id
        final_label = new_label if new_label else cur_label
        final_document = new_document if new_document else cur_document
        final_id = str(new_id) if new_id else str(cur_id)

        # Conflito de label na família alvo
        if final_label in mapping.get(target_family, {}):
            return jsonify({'error': 'Já existe uma subcategoria com este label na família de destino.'}), 409

        # Grava na família alvo
        if target_family not in mapping:
            mapping[target_family] = {}
        mapping[target_family][final_label] = {final_document: final_id}

        save_mapping(mapping)
        return jsonify({'message': 'Categoria atualizada com sucesso.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/categories/<cat_id>', methods=['DELETE'])
@api_token_required
def delete_category(cat_id):
    # Somente admin
    is_admin, _ = _require_admin()
    if not is_admin:
        return jsonify({'error': 'Apenas administradores podem apagar categorias.'}), 403

    try:
        mapping = load_mapping()
        found = find_category_by_id(mapping, cat_id)
        if not found:
            return jsonify({'error': 'Categoria não encontrada.'}), 404

        family = found['family']
        label = found['label']
        try:
            del mapping[family][label]
            if not mapping[family]:
                del mapping[family]
        except KeyError:
            return jsonify({'error': 'Falha ao remover categoria.'}), 500

        save_mapping(mapping)
        return jsonify({'message': 'Categoria removida com sucesso.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
