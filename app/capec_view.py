"""Структурированный текст CAPEC: таблицы, списки и примеры кода."""
from markupsafe import Markup, escape

HTML = {'p', 'div', 'span', 'b', 'i', 'strong', 'em', 'br', 'ul', 'ol', 'li', 'pre', 'code',
        'table', 'thead', 'tbody', 'tr', 'td', 'th', 'blockquote', 'sub', 'sup'}


def plain(node):
    return node['text'] + ''.join(plain(child) + child['tail'] for child in node['children'])


def rich(node, heading=True):
    tag = node['tag']
    content = str(escape(node['text'])) + ''.join(str(rich(c)) for c in node['children'])
    if tag in HTML and node.get('namespace','') in ('','http://www.w3.org/1999/xhtml'):
        attrs = ''
        if tag in ('td', 'th'):
            for key in ('colspan', 'rowspan'):
                value = node['attrs'].get(key, '')
                if str(value).isdigit() and 1 <= int(value) <= 100:
                    attrs += f' {key}="{int(value)}"'
        result = '<br>' if tag == 'br' else f'<{tag}{attrs}>{content}</{tag}>'
    else:
        title = '<strong>' + str(escape(tag.replace('_', ' '))) + '</strong>' if heading else ''
        attrs = ' '.join(str(escape(f'{key}: {value}')) for key, value in node['attrs'].items())
        result = f'<div class="capec-node">{title}<small class="muted">{attrs}</small><div>{content}</div></div>'
    return Markup(result + str(escape(node['tail'])))
