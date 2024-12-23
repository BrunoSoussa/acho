class CategoryMapper:
    def __init__(self):
     
        self.category_mapping = {
            "Consoles e Jogos": "Games",
            "Óculos e itens para oculos": "Óticas",
            "Beleza e Autocuidado": "Beleza",
           "Papelaria e Escritório": "Papelaria",
            "Ferramentas e Equipamentos": "Ferramentas",
            "Brinquedos e jogos educativos": "Brinquedos",
            "Casa e decoração": "Casa e decoração",
            "Materiais de construção": "Material de construção",
             "Itens de Coleção": "Colecionáveis",
            "Instrumentos Musicais": "Música",
            "Brinquedos e Jogos Educativos": "Brinquedos",
            "comidas rápidas e fastfood": "Fast Food",
            "Decoração para Festas": "Festas",
            "Eletrônicos e Gadgets": "Eletrônicos",
            "Veículos automotores incluindo carros e motos": "Veículos",
            "Peças e Acessórios Automotivos": "Autopeças",
            "Produtos Alimentícios Básicos": "Mercado",
            "Itens para Adultos": "Sexshop",
            "Joias e bijuterias": "Joias",
           "Livros e Materiais Literários": "Livros",
            "Esportes": "Esportes",
            "peixaria e Pescados": "Peixaria",
            "Bebidas Alcoólicas": "Bebidas",
            "Padaria e Confeitaria": "Padaria e massas",
            "Acessórios para Pets": "Pets",
            "Doces e Chocolates": "Doces",
            "Presentes e Viagens": "Viagens",
        }

    def map_category(self, category_name):
        """
        Retorna o nome ajustado para a categoria.
        Se não houver mapeamento, retorna o nome original.
        """
        return self.category_mapping.get(category_name, category_name)
