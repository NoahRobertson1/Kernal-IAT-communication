This was a old poc I started in 2023 that I never completed.
The idea was to IAT hook a function that was called by an exported function in win32k.sys, then call the function from usermode with an instance of the communication struct passed into the function.
Once the exported function is called, the hooked function would be called, and could grab the struct out of a registry at runtime, and act accordingly.
Though this was never completed, I thought it was a fun idea for a poc.
