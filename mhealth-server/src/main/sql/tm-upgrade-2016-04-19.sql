--
-- Production upgrade script for the 23andMe database.
--

alter table tm_user_info add (
  create_date timestamp(3)
);

comment on column tm_user_info.create_date is
  'The date when account was created.Null unless the date is set';

alter table tm_download add constraint tm_download_fk
  foreign key (user_id, profile_id) references tm_user_info;
