# 0ctf engineOnline exp

Maybe I am one of the player who did not use the libc very well..

Actually you can write over the gates, and then use the gates to read stack address from heap, and write stack. Only writing a bit of the stack will grant you a gets(), which leads to a cheap shell. Why heap can contain stack address? Because it uses STL. Linked list in STL will contain pointer to std::list::end(), which, if the list is defined in stack, will point to the stack. It is one of cases where heap will contain expensive stack addresses.