# app/schemas/camel_model.py
import datetime # Dodaj import datetime
from pydantic import BaseModel, ConfigDict # Import ConfigDict

"""
OK:
# CamelCase alias generator
def to_camel(string: str) -> str:
    parts = string.split('_')
    return parts[0] + ''.join(word.capitalize() for word in parts[1:])

# Pydantic BaseModel z aliasami camelCase
class CamelModel(BaseModel):
    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True
        orm_mode = True

"""




# CamelCase alias generator (dla konwersji snake_case -> camelCase przy eksporcie)
def to_camel(string: str) -> str:
    """Converts a snake_case string to camelCase."""
    parts = string.split('_')
    return parts[0] + ''.join(word.capitalize() for word in parts[1:])

# SnakeCase alias generator (dla konwersji camelCase -> snake_case przy imporcie)
def to_snake(string: str) -> str:
    """Converts a camelCase string to snake_case."""
    # To jest uproszczona wersja, dla pełnej konwersji użyłbyś biblioteki `humps`
    # lub bardziej zaawansowanej logiki. Pydantic zazwyczaj radzi sobie z tym automatycznie,
    # gdy alias_generator jest używany do generowania aliasów z nazw pól,
    # ale do deserializacji potrzebujemy mapowania.
    # W praktyce, jeśli używasz `alias_generator=to_camel` i `populate_by_name=True`,
    # Pydantic sam dobrze radzi sobie z deserializacją camelCase.
    # Ta funkcja nie jest bezpośrednio używana w ConfigDict jako alias_generator w Pydantic.
    # AliasGenerator w Pydantic v2 działa tak, że przekształca nazwę pola (np. 'user_name')
    # na nazwę aliasu (np. 'userName') w JSON.

    # Dla Pydantic v2 i from_attributes=True, zazwyczaj to wystarczy:
    # model_config = ConfigDict(from_attributes=True, populate_by_name=True, alias_generator=to_camel)
    # Pydantic sam sobie poradzi z deserializacją z obu nazw (nazwa pola i alias).
    # Jeśli nadal masz problemy, możesz użyć humps.convert_to_snake_case bezpośrednio
    # w procesie walidacji lub stworzyć własny RootModel, który to obsługuje.

    # Najprostsze rozwiązanie, które działa z populate_by_name:
    # Użyj to_camel jako alias_generator, a populate_by_name pozwoli na wejście po obu nazwach.
    return string # Ta funkcja nie jest potrzebna jako alias_generator do deserializacji

# Podstawowa klasa BaseModel z automatyczną konwersją snake_case <-> camelCase
class CamelModel(BaseModel):
    # Domyślna konfiguracja dla wszystkich modeli dziedziczących
    model_config = ConfigDict(
        alias_generator=to_camel,        # Generuje aliasy (dla eksportu JSON)
        populate_by_name=True,           # Pozwala na przypisywanie wartości zarówno przez nazwę pola (snake_case), jak i alias (camelCase)
        from_attributes=True,            # Włącza tryb ORM dla Pydantic v2
        json_encoders={datetime.datetime: lambda dt: dt.isoformat()} # Serializacja dat
    )