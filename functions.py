'''
Доступные функции:
- Получение списка сущностей
- Получение схемы сущности
- Получение примера записи
- Поиск по записям по условию
- Создание новой записи, подойдет для:
    - Создания контрагента (Catalog_Контрагенты)
    - Создания платежного поручения (Document_ПлатежноеПоручение)
    - Создания накладной (Document_ПоступлениеТоваровУслуг)
Создание платежного поручения (получить список полей ПП, применить поиск по сущностям, есть ли в них требуемые поля)
- Проведение платежного поручения
* Поиск товара по номенклатуре
* Заполнение таблицы товаров после создания накладной

Создание платежного поручения:
1. LLM получет prompt и обработанный документ.
2. LLM вызывает функцию get_entities для получения списка доступных сущностей.
3. LLM вызывает функцию find_record для поиска контрагента.
4. Если контрагент не был найден, LLM вызывает функцию get_record для получения примера записи контрагента.
5. Если контрагент не был найден, LLM формирует словарь для создания нового контрагента и передает его в функцию create_record.
6. LLM вызывает функцию get_record для получения примера записи платежного поручения.
7. LLM формирует словарь для платежного поручения и передает его в функцию create_record. При создании платежного поручения использовать
данные контрагента. В платежном поручении в поле Контрагент указан Ref_Key соответствующего контрагента.
Возможно, на этом шаге для получения значений полей платежного поручения придется провести поиск по сущностям, чтобы найти требуемые поля.
LLM вызывает функцию get_record для получения списка полей какой-либо сущности, и если в ней найдены требуемые для заполнения платежного
поручения поля, то вызывает функцию find_record для поиска записей, имеющих отношение к текущему создаваемому платежному поручению.
8. При необходимости LLM вызывает функцию post_record для проведения платежного поручения.
9. LLM вызывает функцию get_record для получения примера записи накладной (без номенклатуры).
10. LLM формирует словарь для создания накладной и передает его в функцию create_record. На этом шаге в словаре накладной
"Товары" и "Услуги" всегда равны пустому списку.
11. LLM вызывает функцию get_record для получения примера номенклатуры.
12. LLM вызывает функцию find_record для поиска номенклатур товаров (если существуют).
13. LLM формирует словарь номенклатур для каждого товара и услуги и передает каждый из них по отдельности в функцию add_product_service
соотвественно вместе с соотвествующей им накладной и указанием, передан товар или услуга.
14. LLM получает результат  выполнения последней функции и выдает response.

Создание отчета:
0. Дать явное указание LLM, что если отчет - то выводить результат в виде таблицы
1. LLM определяет документы, которые необходимы для формирования отчета и вызывает функцию get_first_records для каждой сущности для
получения полей и примеров записей.
2. LLM вызывает функцию для получения этих документов (доступны функции get_records_by_date_range, get_records_with_expand, get_aggregated_data).
2. LLM преобразует поулченный результат в таблицу для вывода.
'''


from odata_client import ODataClient
import json
from datetime import datetime
from typing import Optional, List, Dict, Any


def get_entities():
    '''
    Функция получения списка доступных сущностей
    Args:
    Returns:
        Список названий сущностей
        Например, ['Catalog_Контрагенты', 'Catalog_Номенклатура', 'Document_ПлатежноеПоручение']
    '''
    client = ODataClient(
        base_url="http://192.168.18.113/TEST19/odata/standard.odata",
        username="login",
        password="password",
    )
    meta = client.get_metadata()
    entity_sets = (meta.get("entity_sets") or {}).keys()

    return list(entity_sets)


def get_schema(
    entity_name: str
):
    '''
    Функция получения списка полей сущности entity_name
    Args:
        entity_name: наименование сущности (например, 'Catalog_Контрагенты')
    Returns:
        Возвращает список названий сущностей
        Например, ['Catalog_Контрагенты', 'Catalog_Номенклатура', 'Document_ПлатежноеПоручение']
    '''
    client = ODataClient(
        base_url="http://192.168.18.113/TEST19/odata/standard.odata",
        username="login",
        password="password",
    )
    meta = client.get_metadata()
    schema = (meta.get("entity_sets") or {}).get(entity_name, {})
    props = schema.get("properties") or {}

    return list(props.keys())


def get_first_records(
    entity_name: str,
    n: int
):
    '''
    Функция получения примера записи
    Args:
        entity_name: наименование сущности для поиска записей (например, 'Catalog_Контрагенты')
        n: количество записей
    Returns:
        Возвращает первые n записей в виде списка json-словарей или пустой список в случае, если записи не найдены
    '''
    client = ODataClient(
        base_url="http://192.168.18.113/TEST19/odata/standard.odata",
        username="login",
        password="password",
    )

    entity = getattr(client, entity_name)
    sample = entity.top(n).get().values()
    if sample:
        # Если накладная - убираем товары и услуги, так как их добавим позже вместе с проверкой по номенклатурам
        if entity_name == 'Document_ПоступлениеТоваровУслуг':
            for i in range(len(sample)):
                sample[i]["Товары"] = None
                sample[i]["Услуги"] = None
        
        result_dict = json.dumps(sample, ensure_ascii=False)
    else:
        result_dict = []
    
    return result_dict

    

def find_record(
    entity_name: str,
    field: str,
    value: str
):
    '''
    Функция поиска записей по условию: "field eq value"
    Args:
        entity_name: наименование сущности для поиска записей (например, 'Catalog_Контрагенты')
        field: наименование поля для фильтрации по условию
        value: искомое значение в поле field
    Returns:
        Возвращает первую запись в виде json-словаря или пустой словарь в случае, если записи не найдены
    '''
    client = ODataClient(
        base_url="http://192.168.18.113/TEST19/odata/standard.odata",
        username="login",
        password="password",
    )

    entity = getattr(client, entity_name)
    sample = entity.filter(f"{field} eq '{value}'").get().values()
    if sample:
        return json.dumps(sample[0], ensure_ascii=False)
    else:
        return {}
    

def create_record(
    entity_name: str,
    record_dict: dict
):
    '''
    Функция создания новой записи
    Args:
        entity_name: наименование сущности, в которой будет создаваться запись (например, 'Catalog_Контрагенты')
        new_record: словарь, в котором ключи - это поля сущности, значения - это значения записи
        Структура словаря должна полностью соответствовать структуре уже существующих записей в этой сущности
        (примеры уже существующих записей можно получить с помощью функции get_record(entity_name))
    Returns:
        В случае успешного создания - созданную запись в виде json-словаря
        В случае ошибки - словарь с описанием ошибки
    '''
    client = ODataClient(
        base_url="http://192.168.18.113/TEST19/odata/standard.odata",
        username="login",
        password="password",
    )

    try:
        entity = getattr(client, entity_name)
        created_record = entity.create(record_dict)

        if created_record:
            return json.dumbs(created_record, ensure_ascii=False)
        else:
            return {'error': 'Запись не была создана'}
    except Exception as e:
        return {'error': f'Ошибка при создании записи: {str(e)}'}

def post_record(
    entity_name: str,
    ref_key: str
):
    '''
    Функция проведения записи (например, платежного поручения)
    Args:
        entity_name: наименование сущности, в которой существует запись (например, 'Document_ПлатежноеПоручение')
        ref_key: значение поля 'Ref_Key' записи, которую нужно провести
    Returns:
        В случае успешного проведения - словарь с ключом "success" и информацией о проведении
        В случае ошибки - словарь с ключом "error" и описанием проблемы
    '''
    client = ODataClient(
        base_url="http://192.168.18.113/TEST19/odata/standard.odata",
        username="login",
        password="password",
    )
        
    try:
        entity = getattr(client, entity_name)
        record = entity.id(ref_key)
        post_result = record.Post()
        
        # Возвращаем результат проведения
        if post_result:
            return {
                "success": True,
                "message": "Документ успешно проведен",
                "ref_key": ref_key,
                "entity": entity_name
            }
        else:
            return {
                "success": False,
                "error": "Не удалось провести документ",
                "ref_key": ref_key,
                "entity": entity_name
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Ошибка при проведении документа: {str(e)}",
            "ref_key": ref_key,
            "entity": entity_name
        }
    
def add_product_service(
    type_of_good: str,
    waybill_dict: dict,
    product_or_service_dict: dict
):
    '''
    Функция добавляет в словарь накладной один указанный товар
    Args:
        type_of_good: определяется по смыслу поля "Содержание" номенклатуры, может содержать знаечния "Товары" либо "Услуги"
        waybill_dict: словарь накладной
        product_or_service_dict: словарь номенклатуры товара либо услуги
    Returns:
        В случае успешного проведения - словарь с ключом "success" и информацией о проведении
        В случае ошибки - словарь с ключом "error" и описанием проблемы
    '''
    try:
        waybill_dict[type_of_good].append(product_or_service_dict)
        
        return {'success': 'Товар или услуга успешно добавлен(а) в накладную'}
    
    except Exception as e:
        return {'error': f'Произошла ошибка при добавлении товара или услуги: {str(e)}'}
    

def get_records_by_date_range(
    entity_name: str,
    date_field: str = "Date",
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    additional_filters: Optional[Dict[str, Any]] = None,
    top: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Функция получения записей по диапазону дат с дополнительными фильтрами
    
    Args:
        entity_name: наименование сущности для поиска записей (например, 'Document_РеализацияТоваровУслуг')
        date_field: поле даты для фильтрации (по умолчанию "Date")
        start_date: начальная дата диапазона (если None - без ограничения)
        end_date: конечная дата диапазона (если None - текущая дата)
        additional_filters: дополнительные фильтры в формате {"Поле": "Значение"} (необязательно)
        top: Ограничение количества записей (необязательно)
        
    Returns:
        Возвращает найденные записи в виде списка json-словарей или пустой список в случае, если записи не найдены
    """
    client = ODataClient(
        base_url="http://192.168.18.113/TEST19/odata/standard.odata",
        username="login",
        password="password",
    )
    
    entity = getattr(client, entity_name)
    
    # Формирование фильтров к запросу
    filters = []
    if start_date:
        filters.append(f"{date_field} ge datetime'{start_date.isoformat()}'")
    if end_date:
        filters.append(f"{date_field} le datetime'{end_date.isoformat()}'")
    
    if additional_filters:
        for field, value in additional_filters.items():
            if isinstance(value, str):
                filters.append(f"{field} eq '{value}'")
            elif isinstance(value, bool):
                filters.append(f"{field} eq {'true' if value else 'false'}")
            else:
                filters.append(f"{field} eq {value}")
    
    filter_str = " and ".join(filters) if filters else None
    
    query = entity
    if filter_str:
        query = query.filter(filter_str)
    if top:
        query = query.top(top)
    
    response = query.get()
    sample = response.values()

    if sample:
        result_dict = json.dumps(sample, ensure_ascii=False)
    else:
        result_dict = []
    
    return result_dict


def get_records_with_expand(
    entity_name: str,
    expand_fields: List[str],
    filters: Optional[Dict[str, Any]] = None,
    order_by: Optional[str] = None,
    desc: bool = False
) -> List[Dict[str, Any]]:
    """
    Функция получения записей с раскрытием связанных сущностей
    
    Args:
        entity_name: наименование основной сущности
        expand_fields: список полей для раскрытия (например, ["Контрагент_Key", "Организация_Key"])
        filters: фильтры в формате {"Поле": "Значение"} (необязательно)
        order_by: поле для сортировки (необязательно)
        desc: сортировка по убыванию True/False (необязательно)
        
    Returns:
        Возвращает список записей с раскрытыми связанными сущностями
    """
    client = ODataClient(
        base_url="http://192.168.18.113/TEST19/odata/standard.odata",
        username="login",
        password="password",
    )
    
    entity = getattr(client, entity_name)
    
    query = entity.expand(",".join(expand_fields))
    
    if filters:
        filter_parts = []
        for field, value in filters.items():
            if isinstance(value, str):
                filter_parts.append(f"{field} eq '{value}'")
            elif isinstance(value, bool):
                filter_parts.append(f"{field} eq {'true' if value else 'false'}")
            else:
                filter_parts.append(f"{field} eq {value}")
        query = query.filter(" and ".join(filter_parts))
    
    if order_by:
        query = query.filter(f"$orderby={order_by}{' desc' if desc else ''}")
    
    response = query.get()
    sample = response.values()

    if sample:
        result_dict = json.dumps(sample, ensure_ascii=False)
    else:
        result_dict = []
    
    return result_dict


def get_aggregated_data(
    entity_name: str,
    group_by_field: str,
    aggregate_field: str,
    aggregate_func: str = "sum",
    date_field: str = "Date",
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Функция для получения агрегированных данных для построения отчетов
    
    Args:
        entity_name: наименование сущности для получения данных
        group_by_field: поле для группировки
        aggregate_field: поле для агрегации
        aggregate_func: функция агрегации (sum, avg, min, max, count)
        date_field: поле даты для фильтрации (необязательно)
        start_date: начальная дата диапазона (необязательно)
        end_date: конечная дата диапазона (необязательно)
        
    Returns:
        Возвращает ловарь с агрегированными данными в формате {Группа: Значение}, либо ошибку
    """
    records = get_records_by_date_range(
        entity_name=entity_name,
        date_field=date_field,
        start_date=start_date,
        end_date=end_date
    )
    
    # Агрегируем данные
    result = {}
    for record in records:
        group_value = record.get(group_by_field)
        agg_value = record.get(aggregate_field, 0)
        
        if group_value not in result:
            result[group_value] = []
        result[group_value].append(agg_value)
    
    if aggregate_func == "sum":
        return {k: sum(v) for k, v in result.items()}
    elif aggregate_func == "avg":
        return {k: sum(v)/len(v) for k, v in result.items()}
    elif aggregate_func == "min":
        return {k: min(v) for k, v in result.items()}
    elif aggregate_func == "max":
        return {k: max(v) for k, v in result.items()}
    elif aggregate_func == "count":
        return {k: len(v) for k, v in result.items()}
    else:
        raise ValueError(f"Unsupported aggregate function: {aggregate_func}")
    