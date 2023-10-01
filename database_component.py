# Import the SQLAlchemy module and create an engine instance
from sqlalchemy import create_engine
engine = create_engine("sqlite:///malware.db")

# Import the SQLAlchemy declarative base and create a base instance
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

# Import the SQLAlchemy column and relationship modules
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship

# Define the File class, which represents the file table in the database
class File(Base):
    # Define the table name
    __tablename__ = "file"
    # Define the table columns
    id = Column(Integer, primary_key=True)
    name = Column(String)
    size = Column(Integer)
    type = Column(String)
    data = Column(String)
    # Define the table relationships
    md_result = relationship("MDResult", uselist=False, back_populates="file")
    sa_result = relationship("SAResult", uselist=False, back_populates="file")
    da_result = relationship("DAResult", uselist=False, back_populates="file")
    rg_result = relationship("RGResult", uselist=False, back_populates="file")

# Define the MDResult class, which represents the md_result table in the database
class MDResult(Base):
    # Define the table name
    __tablename__ = "md_result"
    # Define the table columns
    id = Column(Integer, primary_key=True)
    name = Column(String)
    type = Column(String)
    family = Column(String)
    origin = Column(String)
    target = Column(String)
    purpose = Column(String)
    infection_vector = Column(String)
    # Define the table relationships
    file_id = Column(Integer, ForeignKey("file.id"))
    file = relationship("File", back_populates="md_result")

# Define the SAResult class, which represents the sa_result table in the database
class SAResult(Base):
    # Define the table name
    __tablename__ = "sa_result"
    # Define the table columns
    id = Column(Integer, primary_key=True)
    format = Column(String)
    architecture = Column(String)
    dependencies = Column(String)
    instructions = Column(String)
    # Define the table relationships
    file_id = Column(Integer, ForeignKey("file.id"))
    file = relationship("File", back_populates="sa_result")

# Define the DAResult class, which represents the da_result table in the database
class DAResult(Base):
    # Define the table name
    __tablename__ = "da_result"
    # Define the table columns
    id = Column(Integer, primary_key=True)
    process = Column(String)
    memory = Column(String)
    registry = Column(String)
    file_system = Column(String)
    api_calls = Column(String)
    persistence_mechanism = Column(String)
    encryption_or_obfuscation_method = Column(String)
    communication_protocol = Column(String)
    network_packets = Column(String)
    # Define the table relationships
    file_id = Column(Integer, ForeignKey("file.id"))
    file = relationship("File", back_populates="da_result")

# Define the RGResult class, which represents the rg_result table in the database
class RGResult(Base):
    # Define the table name
    __tablename__ = "rg_result"
    # Define the table columns
    id = Column(Integer, primary_key=True)
    report = Column(String)
    graph = Column(String)
    table = Column(String)
    visualization = Column(String)
    # Define the table relationships
    file_id = Column(Integer, ForeignKey("file.id"))
    file = relationship("File", back_populates="rg_result")

# Import the SQLAlchemy session module and create a session instance
from sqlalchemy.orm import sessionmaker
Session = sessionmaker(bind=engine)
session = Session()

# Create the database and the tables
Base.metadata.create_all(engine)

# Define the Database class, which provides the methods for the database operations
class Database:
    # Define the save_file method, which saves a file object to the database
    def save_file(self, file):
        # Create a new file object with the file attributes
        new_file = File(name=file.filename, size=file.size, type=file.type, data=file.data)
        # Add the new file object to the session
        session.add(new_file)
        # Commit the session
        session.commit()
        # Return the new file object
        return new_file

    # Define the get_file method, which gets a file object from the database using the file id
    def get_file(self, file_id):
        # Query the file object from the file table using the file id
        file = session.query(File).filter_by(id=file_id).first()
        # Return the file object
        return file

    # Define the save_md_result method, which saves a md_result object to the database
    def save_md_result(self, md_result):
        # Create a new md_result object with the md_result attributes
        new_md_result = MDResult(name=md_result.name, type=md_result.type, family=md_result.family, origin=md_result.origin, target=md_result.target, purpose=md_result.purpose, infection_vector=md_result.infection_vector)
        # Add the new md_result object to the session
        session.add(new_md_result)
        # Commit the session
        session.commit()
        # Return the new md_result object
        return new_md_result

    # Define the get_md_result method, which gets a md_result object from the database using the file id
    def get_md_result(self, file_id):
        # Query the md_result object from the md_result table using the file id
        md_result = session.query(MDResult).filter_by(file_id=file_id).first()
        # Return the md_result object
        return md_result

    # Define the save_sa_result method, which saves a sa_result object to the database
    def save_sa_result(self, sa_result):
        # Create a new sa_result object with the sa_result attributes
        new_sa_result = SAResult(format=sa_result.format, architecture=sa_result.architecture, dependencies=sa_result.dependencies, instructions=sa_result.instructions)
        # Add the new sa_result object to the session
        session.add(new_sa_result)
        # Commit the session
        session.commit()
        # Return the new sa_result object
        return new_sa_result

    # Define the get_sa_result method, which gets a sa_result object from the database using the file id
    def get_sa_result(self, file_id):
        # Query the sa_result object from the sa_result table using the file id
        sa_result = session.query(SAResult).filter_by(file_id=file_id).first()
        # Return the sa_result object
        return sa_result

    # Define the save_da_result method, which saves a da_result object to the database
    def save_da_result(self, da_result):
        # Create a new da_result object with the da_result attributes
        new_da_result = DAResult(process=da_result.process, memory=da_result.memory, registry=da_result.registry, file_system=da_result.file_system, api_calls=da_result.api_calls, persistence_mechanism=da_result.persistence_mechanism, encryption_or_obfuscation_method=da_result.encryption_or_obfuscation_method, communication_protocol=da_result.communication_protocol, network_packets=da_result.network_packets)
        # Add the new da_result object to the session
        session.add(new_da_result)
        # Commit the session
        session.commit()
        # Return the new da_result object
        return new_da_result

    # Define the get_da_result method, which gets a da_result object from the database using the file id
    def get_da_result(self, file_id):
        # Query the da_result object from the da_result table using the file id
        da_result = session.query(DAResult).filter_by(file_id=file_id).first()
        # Return the da_result object
        return da_result

    # Define the save_rg_result method, which saves a rg_result object to the database
    def save_rg_result(self, rg_result):
        # Create a new rg_result object with the rg_result attributes
        new_rg_result = RGResult(report=rg_result.report, graph=rg_result.graph, table=rg_result.table, visualization=rg_result.visualization)
        # Add the new rg_result object to the session
        session.add(new_rg_result)
        # Commit the session
        session.commit()
        # Return the new rg_result object
        return new_rg_result

    # Define the get_rg_result method, which gets a rg_result object from the database using the file id
    def get_rg_result(self, file_id):
        # Query the rg_result object from the rg_result table using the file id
        rg_result = session.query(RGResult).filter_by(file_id=file_id).first()
        # Return the rg_result object
        return rg_result
