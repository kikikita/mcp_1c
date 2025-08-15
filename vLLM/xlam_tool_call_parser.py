# xlam_tool_call_parser.py
import json
from typing import Dict, List, Sequence, Union, Any, Optional

from transformers import PreTrainedTokenizerBase
from vllm.logger import init_logger
from vllm.utils import random_uuid

from vllm.entrypoints.openai.protocol import (
    ChatCompletionRequest,
    DeltaMessage,
    ExtractedToolCallInformation,
    ToolCall,
    FunctionCall,
)
from vllm.entrypoints.openai.tool_parsers.abstract_tool_parser import (
    ToolParser,
    ToolParserManager,
)

logger = init_logger(__name__)


def _json_dumps(x: Any) -> str:
    if isinstance(x, str):
        # предполагаем, что это уже JSON-строка аргументов
        return x
    try:
        return json.dumps(x, ensure_ascii=False)
    except Exception:
        # крайний случай — приводим к строке
        return json.dumps(str(x), ensure_ascii=False)


def _normalize_calls(obj: Any) -> List[Dict[str, Any]]:
    """
    Привести любые распознанные структуры к списку плоских
    {"name": "...", "arguments": ...}.
    Поддерживаются формы:
      - {"name": "...", "arguments": {...}}
      - {"type":"function","function":{"name":"...","arguments":{...}}}
      - {"tool_calls":[{"function":{"name":"...","arguments":{...}}}, ...]}
      - [<любая из форм выше>, ...]
    """
    calls: List[Dict[str, Any]] = []

    def _push(name: Optional[str], args: Any) -> None:
        if not name:
            return
        calls.append({"name": name, "arguments": args})

    def _from_one(node: Any) -> None:
        if not isinstance(node, dict):
            return
        # 1) OpenAI tool_calls-массив
        if "tool_calls" in node and isinstance(node["tool_calls"], list):
            for tc in node["tool_calls"]:
                if isinstance(tc, dict):
                    fn = tc.get("function") or {}
                    _push(fn.get("name"), fn.get("arguments", {}))
            return
        # 2) Обёртка type:function
        if "function" in node and isinstance(node["function"], dict):
            fn = node["function"]
            _push(fn.get("name"), fn.get("arguments", {}))
            return
        # 3) Плоская форма
        _push(node.get("name"), node.get("arguments", {}))

    if isinstance(obj, list):
        for it in obj:
            if isinstance(it, list):
                for sub in it:
                    _from_one(sub)
            else:
                _from_one(it)
    else:
        _from_one(obj)

    return calls


def _to_tool_calls(calls_norm: List[Dict[str, Any]]) -> List[ToolCall]:
    out: List[ToolCall] = []
    for idx, call in enumerate(calls_norm):
        name = call.get("name")
        if not name:
            continue
        args_str = _json_dumps(call.get("arguments", {}))
        out.append(
            ToolCall(
                id=f"call_{idx}_{random_uuid()}",
                type="function",
                function=FunctionCall(name=name, arguments=args_str),
            )
        )
    return out


@ToolParserManager.register_module("xlam")
class xLAMToolParser(ToolParser):
    """
    Надёжный парсер tool-вызовов для моделей, склонных выдавать разные
    формы JSON. Понимает плоскую запись, openai-обёртку и массив tool_calls.
    """

    def __init__(self, tokenizer: PreTrainedTokenizerBase):
        super().__init__(tokenizer)
        # Состояние стриминга можно расширить при необходимости
        self.prev_tool_calls: List[Dict[str, Any]] = []

    @staticmethod
    def extract_first_json(s: str) -> Optional[str]:
        """
        Извлечь первый корректный JSON-объект ИЛИ массив из строки.
        Идём слева направо, ищем '{' ИЛИ '[' и балансируем скобки.
        """
        if not s:
            return None

        n = len(s)
        i = 0
        while i < n:
            ch = s[i]
            if ch not in "{[":
                i += 1
                continue

            stack = [ch]
            j = i + 1
            in_string = False
            escape = False

            while j < n:
                c = s[j]
                if in_string:
                    if escape:
                        escape = False
                    elif c == "\\":
                        escape = True
                    elif c == '"':
                        in_string = False
                    j += 1
                    continue

                if c == '"':
                    in_string = True
                    j += 1
                    continue

                if c in "{[":
                    stack.append(c)
                elif c in "}]":
                    if not stack:
                        return None
                    top = stack[-1]
                    if (top == "{" and c == "}") or (top == "[" and c == "]"):
                        stack.pop()
                        if not stack:
                            candidate = s[i : j + 1]
                            try:
                                # Проверяем, что это валидный JSON
                                json.loads(candidate)
                                return candidate
                            except json.JSONDecodeError:
                                # невалидно — продолжим поиск со следующей позиции
                                break
                    else:
                        # Несогласованная скобка — прервём и продолжим поиск дальше
                        break
                j += 1

            i += 1

        return None

    def extract_tool_calls(
        self, model_output: str, request: ChatCompletionRequest
    ) -> ExtractedToolCallInformation:
        try:
            logger.debug("model_output %s", model_output)
            json_str = self.extract_first_json(model_output)
            if not json_str:
                return ExtractedToolCallInformation(
                    tools_called=False, tool_calls=[], content=model_output
                )

            logger.debug("json_str %s", json_str)
            obj = json.loads(json_str)

            calls_norm = _normalize_calls(obj)
            if not calls_norm:
                return ExtractedToolCallInformation(
                    tools_called=False, tool_calls=[], content=model_output
                )

            tool_calls = _to_tool_calls(calls_norm)
            return ExtractedToolCallInformation(
                tools_called=True, tool_calls=tool_calls, content=model_output
            )

        except Exception:
            logger.exception("Error extracting tool calls")
            return ExtractedToolCallInformation(
                tools_called=False, tool_calls=[], content=model_output
            )

    def extract_tool_calls_streaming(
        self,
        previous_text: str,
        current_text: str,
        delta_text: str,
        previous_token_ids: Sequence[int],
        current_token_ids: Sequence[int],
        delta_token_ids: Sequence[int],
        request: ChatCompletionRequest,
    ) -> Union[DeltaMessage, ExtractedToolCallInformation, None]:
        """
        В стриминге пробуем парсить КАЖДЫЙ раз, как только появляется
        валидный JSON-фрагмент. Если пока не похоже на JSON — возвращаем
        обычный текстовый дельта-чанк.
        """
        try:
            logger.debug("stream model_output %s", current_text)
            json_str = self.extract_first_json(current_text)
            if not json_str:
                return DeltaMessage(delta_text)

            logger.debug("stream json_str %s", json_str)
            obj = json.loads(json_str)

            calls_norm = _normalize_calls(obj)
            if not calls_norm:
                return DeltaMessage(delta_text)

            tool_calls = _to_tool_calls(calls_norm)
            return ExtractedToolCallInformation(
                tools_called=True, tool_calls=tool_calls, content=current_text
            )

        except Exception:
            logger.exception("Error extracting tool calls (streaming)")
            return DeltaMessage(delta_text)
