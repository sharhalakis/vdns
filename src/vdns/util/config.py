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


# Global config options
class Config:
    util = None  # The pre-set utility

    debug = False  # Enable debugging
    what = None  # The action
    module = None  # The acting module


class MergedConfig:
    def __init__(self, *cfgs):
        self.cfgs = cfgs

    def __locate_object(self, name):
        """
        Locate the object that holds the attribute name

        @param name     The attribute to lookup
        @return The object or None
        """
        obj = None

        for cfg in self.cfgs:
            if hasattr(cfg, name):
                obj = cfg
                break

        return obj

    def __getattr__(self, name):
        obj = self.__locate_object(name)

        if not obj:
            raise AttributeError()

        ret = getattr(obj, name)

        return ret

    def __setattr__(self, name, value):
        if name == 'cfgs':
            object.__setattr__(self, name, value)
            return

        obj = self.__locate_object(name)

        if not obj:
            raise AttributeError()

        setattr(obj, name, value)

    def __str__(self):
        cfgstrs = [str(x) for x in self.cfgs]
        ret = 'MergedConfig(%s)' % (', '.join(cfgstrs),)

        return ret


_config = Config()
_module_config = None
_merged_config = MergedConfig(_config)


def set_module_config(cfg):
    """! Point to the module config

    @param cfg      The config object
    """
    global _module_config
    global _merged_config

    _module_config = cfg

    # Re-set this
    _merged_config = MergedConfig(_config, _module_config)


def get_config():
    global _merged_config

    return _merged_config


def __test_merged_config():
    class Obj1:
        t1 = 1
        t2 = 1

    class Obj2:
        t1 = 2
        t3 = 2
        t4 = None

    mo = MergedConfig(Obj1, Obj2)
    print('Merged Object:', mo)
    print()

    print('Merged Before:', mo.t1, mo.t2, mo.t3, mo.t4)
    print('Obj1:', Obj1.t1, Obj1.t2)
    print('Obj2:', Obj2.t1, Obj2.t3, Obj2.t4)

    print()

    mo.t1 = 9
    mo.t2 = 9
    mo.t3 = 9
    mo.t4 = 9

    print('Merged After:', mo.t1, mo.t2, mo.t3, mo.t4)
    print('Obj1:', Obj1.t1, Obj1.t2)
    print('Obj2:', Obj2.t1, Obj2.t3, Obj2.t4)


if __name__ == '__main__':
    __test_merged_config()

# vim: set ts=8 sts=4 sw=4 et formatoptions=r ai nocindent:
