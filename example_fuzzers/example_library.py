def CodeBeingFuzzed(number):
  """Raises an exception if number is 17."""
  if number == 17:
    raise RuntimeError('Number was seventeen!')
    
