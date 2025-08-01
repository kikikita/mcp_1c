import json
import re
from typing import Dict, List, Sequence, Union
import partial_json_parser
from partial_json_parser.core.options import Allow

from vllm.entrypoints.openai.protocol import (
    ChatCompletionRequest, DeltaMessage, DeltaToolCall,
    DeltaFunctionCall, ExtractedToolCallInformation, ToolCall, FunctionCall
)
from vllm.entrypoints.openai.tool_parsers.abstract_tool_parser import ToolParser, ToolParserManager
from vllm.utils import random_uuid
from vllm.logger import init_logger
from transformers import PreTrainedTokenizerBase
from vllm.entrypoints.openai.tool_parsers.utils import (find_common_prefix,
                                                        is_complete_json,
                                                        partial_json_loads)

logger = init_logger(__name__)

@ToolParserManager.register_module("xlam")
class xLAMToolParser(ToolParser):
    def __init__(self, tokenizer: PreTrainedTokenizerBase):
        super().__init__(tokenizer)
        # State for streaming mode
        self.prev_tool_calls: List[Dict] = []
        self.current_tools_sent: List[bool] = []
        self.streamed_args: List[str] = []
        # Remove regex since we're parsing direct JSON

    @staticmethod
    def extract_first_json(s: str) -> str | None:
        pos = 0

        while True:
            start = s.find('{', pos)
            if start < 0:
                return None

            depth = 0
            for i, ch in enumerate(s[start:], start):
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        candidate = s[start:i + 1]
                        try:
                            obj = json.loads(candidate)
                            if isinstance(obj, dict) and not obj:
                                pos = start + 1
                                break
                            return candidate
                        except json.JSONDecodeError:
                            pos = start + 1
                            break
            else:
                return None


    def extract_tool_calls(
        self,
        model_output: str,
        request: ChatCompletionRequest
    ) -> ExtractedToolCallInformation:
        try:
            # Modified: Direct JSON parsing without looking for ```
            json_str = self.extract_first_json(model_output)
            print('model_output', model_output)
            if not json_str:
                return ExtractedToolCallInformation(
                    tools_called=False,
                    tool_calls=[],
                    content=model_output
                )
            print('json_str', json_str)
            json_str = '['+json_str+']'
            tool_calls_data = json.loads(json_str)
            tool_calls: List[ToolCall] = []
            for idx, call in enumerate(tool_calls_data):
                tool_call = ToolCall(
                    id=f"call_{idx}_{random_uuid()}",
                    type="function",
                    function=FunctionCall(
                        name=call["name"],
                        arguments=json.dumps(call["arguments"])
                    )
                )
                tool_calls.append(tool_call)

            return ExtractedToolCallInformation(
                tools_called=True,
                tool_calls=tool_calls,
                content=model_output
            )

        except Exception:
            logger.exception("Error extracting tool calls")
            return ExtractedToolCallInformation(
                tools_called=False,
                tool_calls=[],
                content=model_output
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
        if current_text.endswith("]"):
            try:
                json_str = self.extract_first_json(current_text)
                print('model_output', current_text)
                if not json_str:
                    return ExtractedToolCallInformation(
                        tools_called=False,
                        tool_calls=[],
                        content=model_output
                    )
                print('json_str', json_str)
                json_str = '[' + json_str + ']'
                tool_calls_data = json.loads(json_str)
                tool_calls: List[ToolCall] = []
                for idx, call in enumerate(tool_calls_data):
                    tool_call = ToolCall(
                        id=f"call_{idx}_{random_uuid()}",
                        type="function",
                        function=FunctionCall(
                            name=call["name"],
                            arguments=json.dumps(call["arguments"])
                        )
                    )
                    tool_calls.append(tool_call)

                return ExtractedToolCallInformation(
                    tools_called=True,
                    tool_calls=tool_calls,
                    content=model_output
                )

            except Exception:
                logger.exception("Error extracting tool calls")
                return ExtractedToolCallInformation(
                    tools_called=False,
                    tool_calls=[],
                    content=model_output
                )
        else:
            return DeltaMessage(delta_text)
