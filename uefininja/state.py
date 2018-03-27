class AnalysisState:
    def __init__(self, bv, path):
        self._bv = bv
        self._path = path

    def get_pattern(self):
        return self._pattern

    def set_pattern(self, patt):
        self._pattern = patt.lower()

    def get_path(self):
        return self._path

    def get_binary_view(self):
        return self._bv

    def set_function(self, func):
        self._function = func

    def get_function(self):
        return self._function
