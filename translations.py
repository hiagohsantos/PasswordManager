translations = {
    "pt_BR": {
        "Hello": "Olá",
        "Goodbye": "Adeus",
        "Password Manager": "Gerenciador de Senha",
        "Light Mode": "Modo Claro",
        "No password registered": "Nenhuma senha registrada",
        "Identifier": "Identificador",
        "Password": "Senha",
        "Master Key": "Senha Mestre",
        "Add": "Adicionar",
        "Generate Random": "Gerar Aleatória",
        "Delete": "Apagar",
        "Copy": "Copiar",
        "Error": "Falha",
        "The identifier provided already exists.": "O identificador informado já existe.",
    },
    "es_ES": {
        "Hello": "Hola",
        "Goodbye": "Adiós",
        "Password Manager": "Gestor de Contraseñas",
    },
}

# Configuração de idioma padrão
config = {"lang": "pt_BR"}


def set_language(lang: str) -> None:
    config["lang"] = lang


def _t(text: str) -> str:
    lang = config["lang"]
    return translations.get(lang, {}).get(text, text)


def languages_list() -> list[str]:
    languages_list = ["en_US"]
    languages_list.extend(list(translations.keys()))
    return languages_list
