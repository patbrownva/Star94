import copy
from loguru import logger

from flexget import plugin
from flexget.event import event
from flexget.utils.template import RenderError, render_from_entry

logger = logger.bind(name='inputs')


class PluginConfigInput:
    """
    Configure a plugin with entries from another input.
    """

    schema = {
        'type': 'object',
        'properties': {
            'what': {
                'allOf': [
                    {'$ref': '/schema/plugins?phase=input'},
                    {'maxProperties': 1, 'minProperties': 1},
                ]
            },
            'from': {
                'allOf': [
                    {'$ref': '/schema/plugins?phase=input'},
                    {'maxProperties': 1, 'minProperties': 1},
                ]
            },
            'fields': {'type':'object', 'minProperties': 1},
        },
        'required': ['what','from'],
        'additionalProperties': False,
    }

    def on_task_input(self, task, config):
        from_result = None
        for from_name, from_config in config['from'].items():
            from_input = plugin.get_plugin_by_name(from_name)
            from_method = from_input.phase_handlers['input']
            try:
                from_result = from_method(task, from_config)
            except plugin.PluginError as e:
                logger.warning('Error during input plugin {}: {}', from_name, e)
                continue
            if not from_result:
                msg = 'Input {} did not return anything'.format(from_name)
                if getattr(task, 'no_entries_ok', False):
                    logger.verbose(msg)
                else:
                    logger.warning(msg)
                continue
        entry_titles = set()
        entry_urls = set()
        for entry in from_result:
            if entry['title'] in entry_titles:
                logger.debug('Title `{}` already in entry list, skipping.', entry['title'])
                continue
            #urls = ([entry['url']] if entry.get('url') else []) + entry.get('urls', [])
            #if any(url in entry_urls for url in urls):
            #    logger.debug('URL for `{} already in entry list, skipping.', entry['title'])
            #    continue
            for input_name, input_config in config['what'].items():
                input = plugin.get_plugin_by_name(input_name)
                method = input.phase_handlers['input']
                input_config = copy.copy(input_config)
                try:
                    for field_name, field_template in config['fields'].items():
                        input_config[field_name] = entry.render(field_template)
                except RenderError as e:
                    logger.error('Error rendering {}: {}', field_name, e)
                    continue
                try:
                    input_result = method(task, input_config)
                except plugin.PluginError as e:
                    logger.warning('Error during input plugin {}: {}', input_name, e)
                    continue
                for input_entry in input_result:
                    e = copy.copy(entry)
                    e.update(input_entry)
                    yield e
            entry_titles.add(entry['title'])
            entry_urls.add(entry['url'])

@event('plugin.register')
def register_plugin():
    plugin.register(PluginConfigInput, 'config', api_ver=2)
