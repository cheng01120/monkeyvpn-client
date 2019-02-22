create table shadow (
	username   text not null,
	password   text not null,
	is_online  integer not null default 0,   
	primary key(username)
);

insert into shadow values('zhang', '$6$tkNKQtuTIuviINfz$akkfzJB6fE23VQF.vkX5KUnq6MEOFOScGZhfjAvWWlFSWe0U7vcqM8Tbowsg/CDDZvdvj..hGaiu.3yD0nD9b0', 0);
