__all__ = ['compute_task', 'DoKPI', 'DoGlobalKPI']

# deprecated to keep older scripts who import this from breaking
from .Compute import compute_task
from .DetailedKPI import DoKPI
from .GlobalKPI import DoGlobalKPI