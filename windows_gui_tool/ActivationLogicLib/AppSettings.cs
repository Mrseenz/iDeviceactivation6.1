using System;
using System.IO;
using System.Reflection;

namespace ActivationLogicLib
{
    public static class AppSettings
    {
        public static string DatabaseFileName { get; } = "activation_simulator.sqlite";

        // Provides a flexible way to determine the database path.
        // For a deployed application, the database might be in the application's data directory.
        // For development, it might access the one from the Python project.
        private static string _databasePath = null;

        public static string GetDatabasePath()
        {
            if (_databasePath != null)
            {
                return _databasePath;
            }

            // 1. Try path relative to executing assembly (e.g., bin/Debug/data/activation_simulator.sqlite)
            string assemblyLocation = Assembly.GetExecutingAssembly().Location;
            string assemblyDirectory = Path.GetDirectoryName(assemblyLocation);
            string localDataPath = Path.Combine(assemblyDirectory, "data", DatabaseFileName);
            if (File.Exists(localDataPath))
            {
                _databasePath = localDataPath;
                return _databasePath;
            }

            // 2. Try path relative to current working directory (less reliable for libraries, but good for dev)
            //    (e.g., if running from project root: data/activation_simulator.sqlite)
            string workingDirectory = Directory.GetCurrentDirectory(); // This might be the project root or solution root during dev
            string currentDirDataPath = Path.Combine(workingDirectory, "data", DatabaseFileName);
             if (File.Exists(currentDirDataPath))
            {
                _databasePath = currentDirDataPath;
                return _databasePath;
            }


            // 3. Fallback: Try to locate it from the original Python project structure,
            //    assuming C# project's output (e.g. windows_gui_tool/ActivationLogicLib/bin/Debug/netX.X/)
            //    is somewhat predictably located relative to the Python project.
            //    Path from .../ActivationLogicLib.dll to solution root could be many '..'
            //    Let's try a common structure: solution_root/windows_gui_tool/... and solution_root/py_idevice_activation/...
            string guessPath = assemblyDirectory; // .../bin/Debug/netX.X
            try
            {
                for (int i = 0; i < 5; i++) // Go up a few levels to find a potential common root
                {
                    guessPath = Path.GetDirectoryName(guessPath);
                    if (guessPath == null) break;
                    string potentialPythonDbPath = Path.Combine(guessPath, "py_idevice_activation", "data", DatabaseFileName);
                    if (File.Exists(potentialPythonDbPath))
                    {
                        _databasePath = potentialPythonDbPath;
                        return _databasePath;
                    }
                    // If current 'guessPath' is 'windows_gui_tool', then next level up is solution root.
                    string parentDirName = Path.GetFileName(guessPath);
                    if (parentDirName == "windows_gui_tool") {
                         string solutionRootGuess = Path.GetDirectoryName(guessPath);
                         if(solutionRootGuess != null) {
                            potentialPythonDbPath = Path.Combine(solutionRootGuess, "py_idevice_activation", "data", DatabaseFileName);
                             if (File.Exists(potentialPythonDbPath))
                            {
                                _databasePath = potentialPythonDbPath;
                                return _databasePath;
                            }
                         }
                    }
                }
            } catch (Exception) { /* Path manipulation can fail, ignore */ }


            // 4. Default: Place it in a 'data' subdirectory of where the C# app's .exe is running.
            //    This is a common deployment pattern. The application would be responsible for ensuring this 'data' dir exists.
            //    If this file is used by WinFormsApp, this path will be relative to WinFormsApp.exe
            //    If this library is used by a test project, it'll be relative to that test exe.
            //    For now, let's use the assemblyDirectory as the base for the 'data' folder.
            _databasePath = Path.Combine(assemblyDirectory, "data", DatabaseFileName);

            // The DatabaseManager will attempt to create the directory if it doesn't exist when initializing the schema.
            return _databasePath;
        }

        /// <summary>
        /// Allows overriding the database path, useful for testing or specific configurations.
        /// </summary>
        /// <param name="fullPath">The full path to the SQLite database file.</param>
        public static void SetOverrideDatabasePath(string fullPath)
        {
            _databasePath = fullPath;
        }
    }
}
