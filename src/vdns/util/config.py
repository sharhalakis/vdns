#!/usr/bin/env python
# coding=UTF-8
#

# Config works as follows:
# - There are two configs: The global(util) config and the per-module
#   config. Each one is an object with attributes. To access the config
#   on should call get_config() from here. This will return a MergedConfig
#   object. When it is queried for an attribute it will first look at the
#   global config and then in the module config
# - Each module should call set_module_config() in its add_args()
#   implementation to set its config object. This will update the
#   MergedConfig object to point to the right module object
# - Calling set_module_config() does not invalidate the global config

__all__ = ['get_config', 'set_module_config']

import dataclasses as dc

from typing import Any, Optional


# Global config options
@dc.dataclass
class Config:
    util: Optional[str] = None  # The pre-set utility

    debug: bool = False  # Enable debugging
    what: Optional[str] = None  # The action
    module: Optional[str] = None  # The acting module


class MergedConfig:
    cfgs: tuple[object, ...]

    def __init__(self, *cfgs: object):
        self.cfgs = cfgs

    def __locate_object(self, name: str) -> Optional[object]:
        """Locates the object that holds the attribute name

        @param name     The attribute to lookup
        @return The object or None
        """
        for cfg in self.cfgs:
            if hasattr(cfg, name):
                return cfg
        return None

    def __getattr__(self, name: str) -> Any:
        obj = self.__locate_object(name)

        if not obj:
            raise AttributeError()

        ret = getattr(obj, name)

        return ret

    def __setattr__(self, name: str, value: Any) -> None:
        if name == 'cfgs':
            object.__setattr__(self, name, value)
            return

        obj = self.__locate_object(name)

        if not obj:
            raise AttributeError()

        setattr(obj, name, value)

    def __str__(self) -> str:
        args = ', '.join([str(x) for x in self.cfgs])
        ret = f'MergedConfig({args})'

        return ret


_config: Config = Config()
_module_config: Optional[object] = None
_merged_config: MergedConfig = MergedConfig(_config)


def set_module_config(cfg: object) -> None:
    """! Point to the module config

    @param cfg      The config object
    """
    global _module_config
    global _merged_config

    _module_config = cfg

    # Re-set this
    _merged_config = MergedConfig(_config, _module_config)


def get_config() -> MergedConfig:
    return _merged_config

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
