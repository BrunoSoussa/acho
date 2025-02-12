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

load_dotenv()
os.mkdir("sql") if not os.path.exists("sql") else None
GEMINI_KEY = os.getenv("GEMINI_KEY")
MODEL_NAME = os.getenv("MODEL_NAME")
DB_PATH = "sql/queries_responses.db"
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key") 


print(MODEL_NAME)


app = Flask(__name__)

model = BertForSequenceClassification.from_pretrained(MODEL_NAME)
tokenizer = BertTokenizer.from_pretrained(MODEL_NAME)
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
    
    # Backup dos dados existentes
    cursor.execute("SELECT email, password FROM users")
    existing_users = cursor.fetchall()
    
    # Dropar a tabela antiga
    cursor.execute("DROP TABLE IF EXISTS users")
    
    # Criar a nova tabela com a coluna is_admin
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            created_at TEXT DEFAULT (DATETIME('now'))
        )
    """)
    
    # Restaurar os dados existentes
    for user in existing_users:
        cursor.execute("""
            INSERT INTO users (email, password, is_admin)
            VALUES (?, ?, 0)
        """, (user[0], user[1]))
    
    conn.commit()
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
    
    conn.commit()
    conn.close()

# Inicialização do banco de dados
create_tables()
migrate_database()  # Adicione esta linha para executar a migração

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
            response.set_cookie('token', token, httponly=True, secure=True, samesite='Strict')
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
            {"id": row[0], "query": row[1], "degree_of_certainty": row[2], "category": row[3], "category_id": row[4], "created_at": row[5]}
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

if __name__ == "__main__":
    app.run(debug=True)
# Salvar no banco de dados
