#include "./../../includes/ft_ping.h"

t_list *lst_new(void *data)
{
	t_list *new;

	new = malloc(sizeof(t_list));
	if (new == NULL)
		return NULL;
	new->data = data;
	new->next = NULL;
	return new;
}

void lst_add_back(t_list **lst, t_list *new)
{
	t_list *aux;

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

void free_list(t_list **lst)
{
	t_list *aux = *lst;

	while (aux != NULL)
	{
		aux = (*lst)->next;
		free((*lst)->data);
		free(*lst);
		*lst = aux;
	}
}

// need this function because of the fuckin strdup, i was happier when I just override the memory, fuck my life
void free_list_data(t_list **lst)
{
	t_list *aux = *lst;

	while (aux != NULL)
	{
		aux = (*lst)->next;
		free(((t_host_info *)((*lst)->data))->hostname);
		free((*lst)->data);
		free(*lst);
		*lst = aux;
	}
}