//#define BOOST_NO_SCOPED_ENUMS
#include <fc/filesystem.hpp>
#include <fc/exception/exception.hpp>
#include <fc/fwd_impl.hpp>
#include <fc/utility.hpp>

#include <fc/utf8.hpp>
#include <fc/variant.hpp>

#include <boost/config.hpp>

#include <fstream>

#ifdef _WIN32
# include <windows.h>
# include <userenv.h>
# include <shlobj.h>
#else
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <pwd.h>
# ifdef FC_HAS_SIMPLE_FILE_LOCK
  #include <sys/file.h>
  #include <fcntl.h>
# endif
#endif

namespace fc {
  // when converting to and from a variant, store utf-8 in the variant
  void to_variant( const std::filesystem::path& path_to_convert, variant& variant_output )
  {
    std::wstring wide_string = path_to_convert.generic_wstring();
    std::string utf8_string;
    fc::encodeUtf8(wide_string, &utf8_string);
    variant_output = utf8_string;

    //std::string path = t.to_native_ansi_path();
    //std::replace(path.begin(), path.end(), '\\', '/');
    //v = path;
  }

  void from_variant( const fc::variant& variant_to_convert, std::filesystem::path& path_output )
  {
    std::wstring wide_string;
    fc::decodeUtf8(variant_to_convert.as_string(), &wide_string);
    path_output = path(wide_string);
  }

  // setuid, setgid not implemented.
  // translates octal permission like 0755 to S_ stuff defined in sys/stat.h
  // no-op on Windows.
  void chmod( const path& p, int perm )
  {
#ifndef WIN32
    mode_t actual_perm =
      ((perm & 0400) ? S_IRUSR : 0)
    | ((perm & 0200) ? S_IWUSR : 0)
    | ((perm & 0100) ? S_IXUSR : 0)

    | ((perm & 0040) ? S_IRGRP : 0)
    | ((perm & 0020) ? S_IWGRP : 0)
    | ((perm & 0010) ? S_IXGRP : 0)

    | ((perm & 0004) ? S_IROTH : 0)
    | ((perm & 0002) ? S_IWOTH : 0)
    | ((perm & 0001) ? S_IXOTH : 0)
    ;

    int result = ::chmod( p.string().c_str(), actual_perm );
    if( result != 0 )
        FC_THROW( "chmod operation failed on ${p}", ("p",p) );
#endif
    return;
  }

  path     unique_path() { return path(std::tmpnam(nullptr)); }
  path     temp_directory_path() { return std::filesystem::temp_directory_path(); }


   temp_file::temp_file(const std::filesystem::path& p, bool create)
   : temp_file_base(p / fc::unique_path())
   {
      if (std::filesystem::exists(*_path))
      {
         FC_THROW( "Name collision: ${path}", ("path", _path->string()) );
      }
      if (create)
      {
         std::ofstream ofs(_path->generic_string().c_str(), std::ofstream::out | std::ofstream::binary);
         ofs.close();
      }
   }

   temp_file::temp_file(temp_file&& other)
      : temp_file_base(std::move(other._path))
   {
   }

   temp_file& temp_file::operator=(temp_file&& other)
   {
      if (this != &other)
      {
         remove();
         _path = std::move(other._path);
      }
      return *this;
   }

   temp_directory::temp_directory(const std::filesystem::path& p)
   : temp_file_base(p / fc::unique_path())
   {
      if (std::filesystem::exists(*_path))
      {
         FC_THROW( "Name collision: ${path}", ("path", _path->string()) );
      }
      std::filesystem::create_directories(*_path);
   }

   temp_directory::temp_directory(temp_directory&& other)
      : temp_file_base(std::move(other._path))
   {
   }

   temp_directory& temp_directory::operator=(temp_directory&& other)
   {
      if (this != &other)
      {
         remove();
         _path = std::move(other._path);
      }
      return *this;
   }

   const std::filesystem::path& temp_file_base::path() const
   {
      if (!_path)
      {
         FC_THROW( "Temporary directory has been released." );
      }
      return *_path;
   }

   void temp_file_base::remove()
   {
      if (_path)
      {
         try
         {
            std::filesystem::remove_all(*_path);
         }
         catch (...)
         {
            // eat errors on cleanup
         }
         release();
      }
   }

   void temp_file_base::release()
   {
      _path = std::optional<std::filesystem::path>();
   }

   const std::filesystem::path& home_path()
   {
      static std::filesystem::path p = []()
      {
#ifdef WIN32
          HANDLE access_token;
          if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &access_token))
            FC_ASSERT(false, "Unable to open an access token for the current process");
          wchar_t user_profile_dir[MAX_PATH];
          DWORD user_profile_dir_len = sizeof(user_profile_dir);
          BOOL success = GetUserProfileDirectoryW(access_token, user_profile_dir, &user_profile_dir_len);
          CloseHandle(access_token);
          if (!success)
            FC_ASSERT(false, "Unable to get the user profile directory");
          return std::filesystem::path(std::wstring(user_profile_dir));
#else
          char* home = getenv( "HOME" );
          if( nullptr == home )
          {
             struct passwd* pwd = getpwuid(getuid());
             if( pwd )
             {
                 return std::filesystem::path( std::string( pwd->pw_dir ) );
             }
             FC_ASSERT( home != nullptr, "The HOME environment variable is not set" );
          }
          return std::filesystem::path( std::string(home) );
#endif
      }();
      return p;
   }

   const std::filesystem::path& app_path()
   {
#ifdef __APPLE__
         static std::filesystem::path appdir = [](){  return home_path() / "Library" / "Application Support"; }();
#elif defined( WIN32 )
         static std::filesystem::path appdir = [](){
           wchar_t app_data_dir[MAX_PATH];

           if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, app_data_dir)))
             FC_ASSERT(false, "Unable to get the current AppData directory");
           return std::filesystem::path(std::wstring(app_data_dir));
         }();
#else
        static std::filesystem::path appdir = home_path() / ".local/share";
#endif
      return appdir;
   }

   const std::filesystem::path& current_path()
   {
     static std::filesystem::path appCurrentPath = std::filesystem::current_path();
     return appCurrentPath;
   }


#ifdef FC_HAS_SIMPLE_FILE_LOCK
  class simple_lock_file::impl
  {
  public:
#ifdef _WIN32
    HANDLE file_handle;
#else
    int file_handle;
#endif
    bool is_locked;
    path lock_file_path;

    impl(const path& lock_file_path);
    ~impl();

    bool try_lock();
    void unlock();
  };

  simple_lock_file::impl::impl(const path& lock_file_path) :
#ifdef _WIN32
    file_handle(INVALID_HANDLE_VALUE),
#else
    file_handle(-1),
#endif
    is_locked(false),
    lock_file_path(lock_file_path)
  {}

  simple_lock_file::impl::~impl()
  {
    unlock();
  }

  bool simple_lock_file::impl::try_lock()
  {
#ifdef _WIN32
    HANDLE fh = CreateFileA(lock_file_path.to_native_ansi_path().c_str(),
                            GENERIC_READ | GENERIC_WRITE,
                            0, 0,
                            OPEN_ALWAYS, 0, NULL);
    if (fh == INVALID_HANDLE_VALUE)
      return false;
    is_locked = true;
    file_handle = fh;
    return true;
#else
    int fd = open(lock_file_path.string().c_str(), O_RDWR|O_CREAT, 0644);
    if (fd < 0)
      return false;
    if (flock(fd, LOCK_EX|LOCK_NB) == -1)
    {
      close(fd);
      return false;
    }
    is_locked = true;
    file_handle = fd;
    return true;
#endif
  }

  void simple_lock_file::impl::unlock()
  {
#ifdef WIN32
    CloseHandle(file_handle);
    file_handle = INVALID_HANDLE_VALUE;
    is_locked = false;
#else
    flock(file_handle, LOCK_UN);
    close(file_handle);
    file_handle = -1;
    is_locked = false;
#endif
  }


  simple_lock_file::simple_lock_file(const path& lock_file_path) :
    my(new impl(lock_file_path))
  {
  }

  simple_lock_file::~simple_lock_file()
  {
  }

  bool simple_lock_file::try_lock()
  {
    return my->try_lock();
  }

  void simple_lock_file::unlock()
  {
    my->unlock();
  }
#endif // FC_HAS_SIMPLE_FILE_LOCK

}
