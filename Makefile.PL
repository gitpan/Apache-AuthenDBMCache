# $Id: Makefile.PL,v 1.4 2002/10/29 15:06:45 reggers Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Apache::AuthenDBMCache',
   DISTNAME      => 'Apache-AuthenDBMCache',
   VERSION_FROM  => 'AuthenDBMCache.pm',

   PREREQ_PM     => {
	MD5 => 0
   },

   dist          => { 
	COMPRESS=>"gzip",
	SUFFIX=>"gz"
   }
);
