from fastapi.templating import Jinja2Templates
from typing import Optional, Dict, Any
import jinja2


class XMLRenderer:
  def __init__(self, directory: str = "config/wk"):
    """
    Inicjalizacja renderera XML.

    :param directory: Ścieżka do katalogu z szablonami (domyślnie 'templates')
    """
    # Konfiguracja Jinja2 specjalnie dla XML (autoescape domyślnie włączony)
    self.templates = Jinja2Templates(
      directory=directory,
      autoescape=True,
      auto_reload=True  # W development, w produkcji powinno być False
    )

    # Domyślne rozszerzenie dla szablonów XML
    self.templates.env.auto_reload = True
    self.templates.env.lstrip_blocks = True
    self.templates.env.trim_blocks = True

  async def render_to_string(
      self,
      template_name: str,
      context: Optional[Dict[str, Any]] = None,
      request=None
  ) -> str:
    """
    Renderuje szablon XML do stringa.

    :param template_name: Nazwa pliku szablonu (np. 'api/response.xml')
    :param context: Kontekst z danymi do szablonu
    :param request: Obiekt request FastAPI (opcjonalny)
    :return: Wyrenderowany XML jako string
    """
    if context is None:
      context = {}

    if request is not None:
      context["request"] = request

    template = self.templates.get_template(template_name)
    return template.render(context)

  async def render_to_response(
      self,
      template_name: str,
      context: Optional[Dict[str, Any]] = None,
      request=None,
      headers: Optional[Dict[str, str]] = None,
      status_code: int = 200
  ):
    """
    Renderuje szablon XML do odpowiedzi FastAPI.

    :param template_name: Nazwa pliku szablonu
    :param context: Kontekst z danymi do szablonu
    :param request: Obiekt request FastAPI
    :param headers: Dodatkowe nagłówki HTTP
    :param status_code: Kod statusu HTTP
    :return: Response z wyrenderowanym XML
    """
    from fastapi.responses import Response

    xml_content = await self.render_to_string(template_name, context, request)

    response_headers = {"Content-Type": "application/xml"}
    if headers:
      response_headers.update(headers)

    return Response(
      content=xml_content,
      media_type="application/xml",
      headers=response_headers,
      status_code=status_code
    )

# Przykład użycia:
# 1. Inicjalizacja (zwykle w pliku z zależnościami)
# xml_renderer = XMLRenderer(directory="app/templates")

# 2. W endpointcie FastAPI:
# @app.get("/api/data.xml", response_class=Response)
# async def get_xml_data(request: Request):
#     context = {"items": [1, 2, 3], "name": "Test"}
#     return await xml_renderer.render_to_response("data.xml", context, request)

