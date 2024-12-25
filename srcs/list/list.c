#include "./../../includes/ft_ping.h"

t_timeval *lst_new(double timeval)
{
	t_timeval *new;

	new = malloc(sizeof(t_timeval));
	if (new == NULL)
		return NULL;
	new->timeval = timeval;
	new->next = NULL;
	return new;
}

void lst_add_back(t_timeval **lst, t_timeval *new)
{
	t_timeval *aux;

	aux = *lst;
	if (*lst == NULL)
		*lst = new;
	else
	{
		while (aux->next != NULL)
			aux = aux->next;
		aux->next = new;		
	}
}

void free_list(t_timeval **lst)
{
	t_timeval *aux = *lst;

	while (aux != NULL)
	{
		aux = (*lst)->next;
		free(*lst);
		*lst = aux;
	}
}