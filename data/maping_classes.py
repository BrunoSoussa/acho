class CategoryMapper:
    def __init__(self):
     
        self.category_mapping = {
    "consoles e jogos": "Games",
    "óculos e itens para oculos": "Óticas",
    "beleza e autocuidado": "Beleza",
    "papelaria e escritório": "Papelaria",
    "ferramentas e equipamentos": "Ferramentas",
    "brinquedos e jogos educativos": "Brinquedos",
    "casa e decoração": "Casa e decoração",
    "materiais de construção": "Material de construção",
    "itens de coleção": "Colecionáveis",
    "instrumentos musicais": "Música",
    "comidas rápidas e fastfood": "Fast Food",
    "decoração para festas": "Festas",
    "eletrônicos e gadgets": "Eletrônicos",
    "veículos automotores incluindo carros e motos": "Veículos",
    "peças e acessórios automotivos": "Autopeças",
    "produtos alimentícios básicos": "Mercado",
    "itens para adultos como brinquedos sexuais": "Sexshop",
    "joias e bijuterias": "Joias",
    "livros e materiais literários": "Livros",
    "esportes": "Esportes",
    "peixaria e pescados": "Peixaria",
    "bebidas alcoólicas": "Bebidas",
    "padaria e confeitaria": "Padaria",
    "produtos para pets e animais domésticos": "Pets",
    "doces e chocolates": "Doces",
    "presentes e viagens": "Viagens",
    "serviços de desenvolvimento de software":"Desenv. Software",
    "serviços na área da educação":"Serviço Educação"

}

    def map_category(self, category_name):
        """
        Retorna o nome ajustado para a categoria.
        Se não houver mapeamento, retorna o nome original.
        """
        return self.category_mapping.get(category_name, category_name)
