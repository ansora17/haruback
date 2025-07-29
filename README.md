# Harukcal - Spring Boot Application

A Spring Boot application for calorie tracking and meal management with user authentication, profile management, and image processing capabilities.

## 🚀 Features

- **User Authentication**: JWT-based authentication with refresh tokens
- **Profile Management**: User profiles with image upload support
- **Image Processing**: Automatic image compression, thumbnail generation, and smart naming
- **Calorie Calculation**: Mifflin-St Jeor equation for recommended daily calories
- **CORS Support**: Global CORS configuration for frontend integration
- **Database Integration**: MySQL database with JPA/Hibernate
- **File Upload**: Support for profile images with Supabase storage integration

## 📋 Prerequisites

- **Java 17** or higher
- **MySQL 8.0** or higher
- **Gradle 7.0** or higher (or use the included Gradle wrapper)

## 🛠️ Setup Instructions

### 1. Database Setup

1. Create a MySQL database named `harukcal2`
2. Update database configuration in `src/main/resources/application.properties`:

```properties
spring.datasource.url=jdbc:mysql://localhost:3306/harukcal2?useSSL=false&serverTimezone=Asia/Seoul&characterEncoding=UTF-8&allowPublicKeyRetrieval=true
spring.datasource.username=your_username
spring.datasource.password=your_password
```

### 2. File Upload Directory

Create the upload directory for images:

```bash
# Windows
mkdir C:\upload

# Linux/Mac
mkdir /upload
```

### 3. Supabase Configuration (Optional)

If using Supabase for image storage, update the configuration in `application.properties`:

```properties
supabase.url=your_supabase_url
supabase.bucket=your_bucket_name
supabase.anon-key=your_anon_key
supabase.service-role-key=your_service_role_key
```

## 🏃‍♂️ Running the Application

### Using Gradle Wrapper (Recommended)

```bash
# Clean and build
./gradlew clean build

# Run the application
./gradlew bootRun
```

### Using Gradle (if installed globally)

```bash
# Clean and build
gradle clean build

# Run the application
gradle bootRun
```

### Using Java JAR

```bash
# Build JAR
./gradlew build

# Run JAR
java -jar build/libs/haruSpring-main-0.0.1-SNAPSHOT.jar
```

## 🌐 Application Endpoints

The application runs on **port 8081** by default.

### Health Check

- `GET /api/health` - Application health status

### Authentication

- `POST /api/members/login` - User login
- `POST /api/members/logout` - User logout
- `POST /api/members/refresh` - Refresh JWT token

### User Management

- `POST /api/members/multipart` - Create user with profile image
- `GET /api/members/me` - Get current user profile
- `PUT /api/members/me` - Update user profile
- `PATCH /api/members/me/profile-image` - Update profile image URL

### Image Processing

- `POST /api/members/upload-image` - Upload and process image
- `POST /api/members/me/upload-profile-image` - Upload and process profile image

### Calorie Calculation

- `GET /api/members/me/recommended-calories-calculation` - Get recommended daily calories

### Utility Endpoints

- `GET /api/members/check-email` - Check email availability
- `GET /api/members/check-nickname` - Check nickname availability
- `POST /api/members/search-nickname` - Search for nickname
- `POST /api/members/reset-password` - Request password reset

## 🔧 Configuration

### Server Configuration

- **Port**: 8081 (configurable in `application.properties`)
- **Context Path**: `/` (root)

### Database Configuration

- **Dialect**: MySQL 8
- **DDL Auto**: Update (automatically updates schema)
- **Show SQL**: Enabled for debugging

### File Upload Configuration

- **Max File Size**: 10MB
- **Upload Directory**: `C:/upload/` (Windows) or `/upload/` (Linux/Mac)

### Image Processing Configuration

- **Max Width**: 1200px
- **Max Height**: 1200px
- **Thumbnail Size**: 200px
- **Quality**: 80%
- **Thumbnail Quality**: 70%

## 🔒 Security Features

- **JWT Authentication**: Stateless authentication with access and refresh tokens
- **CORS Configuration**: Global CORS support for frontend integration
- **CSRF Protection**: Disabled for REST API
- **Session Management**: Stateless sessions
- **Password Encryption**: BCrypt password hashing

## 📁 Project Structure

```
src/main/java/com/study/spring/
├── domain/
│   ├── board/          # Board management
│   ├── issue/          # Issue tracking
│   ├── meal/           # Meal management
│   ├── member/         # User management
│   └── security/       # Security configuration
├── HarukcalApplication.java
└── ServletInitializer.java
```

## 🐛 Troubleshooting

### Port Already in Use

If port 8081 is already in use, change the port in `application.properties`:

```properties
server.port=8082
```

### Database Connection Issues

1. Ensure MySQL is running
2. Check database credentials
3. Verify database exists
4. Check network connectivity

### File Upload Issues

1. Ensure upload directory exists and has write permissions
2. Check file size limits
3. Verify file format support

### CORS Issues

The application includes global CORS configuration for:

- `http://localhost:*`
- `http://127.0.0.1:*`
- `https://localhost:*`
- `https://127.0.0.1:*`

## 📝 API Documentation

### Authentication Flow

1. User logs in via `POST /api/members/login`
2. Application sets JWT cookies (accessToken, refreshToken, userData)
3. Subsequent requests use JWT for authentication
4. Tokens are automatically refreshed when needed

### Image Upload Flow

1. Upload image via `POST /api/members/me/upload-profile-image`
2. Image is processed (compressed, thumbnail generated)
3. Files are saved with timestamp naming (YYMMDDHHMM_filename)
4. Profile image URL is updated in database and cookies

### Calorie Calculation

- Uses Mifflin-St Jeor equation
- Calculated on-demand via `GET /api/members/me/recommended-calories-calculation`
- No persistent storage of target calories (frontend-only calculation)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For issues and questions:

1. Check the troubleshooting section
2. Review application logs
3. Create an issue in the repository
